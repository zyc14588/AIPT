package web

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/zyc14588/AIPT/internal/config"
	"github.com/zyc14588/AIPT/internal/runcontrol"
	"github.com/zyc14588/AIPT/internal/storage/postgres"
)

type operationalTestQueue struct {
	runcontrol.Queue
	mu     sync.Mutex
	paused bool
}

func (q *operationalTestQueue) Snapshot(context.Context, int) (runcontrol.QueueSnapshot, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	return runcontrol.QueueSnapshot{Paused: q.paused, Records: []postgres.RunRecord{{RunID: "record-a", ManifestCanonical: []byte("PRIVATE_PROMPT_BODY_SENTINEL")}}}, nil
}
func (q *operationalTestQueue) SetQueuePaused(ctx context.Context, paused bool, reason string) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	q.paused = paused
	return nil
}
func operationalTestHost(t *testing.T) (*Host, *runcontrol.Service) {
	t.Helper()
	cfg, err := config.Load([]byte(`{"schema":"aipt.config/v1","profile":"development","database":{"identity":"control_dev","namespace":"control_dev","dsn":"postgresql://private:private@127.0.0.1/control_dev","ping_timeout_ms":1000},"evidence":{"namespace":"control-dev"}}`))
	if err != nil {
		t.Fatal(err)
	}
	q := &operationalTestQueue{}
	service, err := runcontrol.New(runcontrol.Options{Queue: q, Reader: q, Lifetime: context.Background(), HolderID: "holder", LeaseDuration: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	host, err := StartOperational(context.Background(), cfg, service)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := host.Stop(ctx); err != nil {
			t.Error(err)
		}
		if err := service.Stop(ctx); err != nil {
			t.Error(err)
		}
	})
	return host, service
}
func controlRequest(t *testing.T, host *Host, method, path, origin, token, kind, body string) (int, []byte, http.Header) {
	t.Helper()
	request, err := http.NewRequest(method, host.URL()+path, strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	if token != "" {
		request.Header.Set("X-AIPT-CSRF", token)
	}
	if kind != "" {
		request.Header.Set("Content-Type", kind)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, data, response.Header
}
func TestOperationalSessionAndWebStdioShareAuthoritativeService(t *testing.T) {
	host, service := operationalTestHost(t)
	status, body, _ := controlRequest(t, host, "GET", "/api/v1/session", "", "", "", "")
	if status != 200 {
		t.Fatal(status)
	}
	var session struct {
		Token string `json:"csrf_token"`
	}
	if err := json.Unmarshal(body, &session); err != nil || session.Token != host.csrfToken {
		t.Fatal("wrong session token")
	}
	raw := `{"jsonrpc":"2.0","protocol_version":1,"id":"web-a","method":"aipt.v1.queue.pause","params":{"paused":true}}`
	status, body, headers := controlRequest(t, host, "POST", "/api/v1/control", host.URL(), session.Token, "application/json", raw)
	if status != 200 {
		t.Fatalf("%d %s", status, body)
	}
	if headers.Get("Cache-Control") != "no-store" || headers.Get("Access-Control-Allow-Origin") != "" {
		t.Fatal("response not protected")
	}
	snapshot, err := service.Snapshot(context.Background(), 100)
	if err != nil || !snapshot.Paused {
		t.Fatal("HTTP used a separate queue")
	}
	input, send := io.Pipe()
	receive, output := io.Pipe()
	defer send.Close()
	defer receive.Close()
	rpc, err := runcontrol.StartRPC(context.Background(), input, output, service)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	defer rpc.Stop(ctx)
	rpcRaw := strings.Replace(raw, `"paused":true`, `"paused":false`, 1)
	sent := make(chan error, 1)
	go func() { _, err := fmt.Fprintf(send, "Content-Length: %d\r\n\r\n%s", len(rpcRaw), rpcRaw); sent <- err }()
	reader := bufio.NewReader(receive)
	header, err := reader.ReadString('\n')
	if err != nil {
		t.Fatal(err)
	}
	var size int
	if _, err := fmt.Sscanf(header, "Content-Length: %d", &size); err != nil {
		t.Fatal(err)
	}
	_, _ = reader.ReadString('\n')
	encoded := make([]byte, size)
	if _, err := io.ReadFull(reader, encoded); err != nil {
		t.Fatal(err)
	}
	if err := <-sent; err != nil {
		t.Fatal(err)
	}
	status, body, _ = controlRequest(t, host, "GET", "/api/v1/dashboard", "", "", "", "")
	if status != 200 {
		t.Fatal(status)
	}
	var dashboard OperationalDashboard
	if err := json.Unmarshal(body, &dashboard); err != nil || dashboard.Control.Paused {
		t.Fatal("stdio update not visible in HTTP")
	}
	for _, private := range []string{"PRIVATE_PROMPT_BODY_SENTINEL", "postgresql://", "dsn", "csrf_token", "lease_token", "domain_state"} {
		if bytes.Contains(body, []byte(private)) {
			t.Fatalf("dashboard leaked %s", private)
		}
	}
}
func TestOperationalMutationAndBootstrapSecurity(t *testing.T) {
	host, _ := operationalTestHost(t)
	raw := `{"jsonrpc":"2.0","protocol_version":1,"id":"web-a","method":"aipt.v1.queue.pause","params":{"paused":true}}`
	cases := []struct {
		name, method, path, origin, token, kind, body string
		status                                        int
	}{
		{"no-origin", "POST", "/api/v1/control", "", host.csrfToken, "application/json", raw, 403},
		{"cross-origin", "POST", "/api/v1/control", "https://evil.invalid", host.csrfToken, "application/json", raw, 403},
		{"no-csrf", "POST", "/api/v1/control", host.URL(), "", "application/json", raw, 403},
		{"wrong-csrf", "POST", "/api/v1/control", host.URL(), "wrong", "application/json", raw, 403},
		{"form-content", "POST", "/api/v1/control", host.URL(), host.csrfToken, "text/plain", raw, 415},
		{"case-alias", "POST", "/api/v1/control", host.URL(), host.csrfToken, "application/json", strings.Replace(raw, `"params"`, `"Params"`, 1), 400},
		{"unknown-method", "POST", "/api/v1/control", host.URL(), host.csrfToken, "application/json", strings.Replace(raw, "queue.pause", "lease.complete", 1), 404},
		{"oversize", "POST", "/api/v1/control", host.URL(), host.csrfToken, "application/json", strings.Repeat("x", runcontrol.MaxRequestBytes+1), 413},
		{"session-cross-origin", "GET", "/api/v1/session", "https://evil.invalid", "", "", "", 403},
		{"session-query", "GET", "/api/v1/session?token=wrong", "", "", "", "", 404},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			status, _, _ := controlRequest(t, host, test.method, test.path, test.origin, test.token, test.kind, test.body)
			if status != test.status {
				t.Fatalf("status=%d want=%d", status, test.status)
			}
		})
	}
	for _, field := range []struct{ name, value string }{{"Host", "localhost:1234"}, {"Sec-Fetch-Site", "cross-site"}} {
		request, _ := http.NewRequest("GET", host.URL()+"/api/v1/session", nil)
		if field.name == "Host" {
			request.Host = field.value
		} else {
			request.Header.Set(field.name, field.value)
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		if response.StatusCode != 403 {
			t.Fatal("bootstrap guard bypassed")
		}
	}
	snapshot, err := func() (runcontrol.Snapshot, error) {
		_, s := operationalTestHost(t)
		return s.Snapshot(context.Background(), 100)
	}()
	if err != nil || snapshot.Paused {
		t.Fatal("fresh service not isolated")
	}
}
func TestOperationalServedArtifactAndSixPanels(t *testing.T) {
	host, _ := operationalTestHost(t)
	status, html, headers := controlRequest(t, host, "GET", "/", "", "", "", "")
	if status != 200 || !strings.Contains(headers.Get("Content-Security-Policy"), "frame-ancestors 'none'") {
		t.Fatal("unprotected document")
	}
	for _, id := range []string{"queue-title", "run-title", "seat-title", "reports-title", "config-title", "health-title"} {
		if !bytes.Contains(html, []byte(`id="`+id+`"`)) {
			t.Fatal("missing panel " + id)
		}
	}
	status, js, _ := controlRequest(t, host, "GET", "/assets/controls.js", "", "", "", "")
	if status != 200 || bytes.Contains(js, []byte("innerHTML")) || bytes.Contains(js, []byte("localStorage")) {
		t.Fatal("unsafe served UI")
	}
	if _, err := StartOperational(context.Background(), nil, nil); err == nil {
		t.Fatal("missing shared service accepted")
	}
}
