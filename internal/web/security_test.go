package web

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func startSecurityTestHost(t *testing.T, handler http.Handler) (*Host, *http.Client) {
	t.Helper()
	host, err := StartHost(context.Background(), handler)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := host.Stop(ctx); err != nil {
			t.Errorf("Stop: %v", err)
		}
	})
	return host, &http.Client{Timeout: 2 * time.Second}
}

func request(t *testing.T, client *http.Client, method, target, hostHeader, origin, csrf string) (*http.Response, string) {
	t.Helper()
	req, err := http.NewRequest(method, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if hostHeader != "" {
		req.Host = hostHeader
	}
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	if csrf != "" {
		req.Header.Set("X-AIPT-CSRF", csrf)
	}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, err := io.ReadAll(response.Body)
	response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	return response, string(body)
}

func TestHostBindsDynamicIPv4Loopback(t *testing.T) {
	host, _ := startSecurityTestHost(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	parsed, err := url.Parse(host.URL())
	if err != nil {
		t.Fatal(err)
	}
	address, err := net.ResolveTCPAddr("tcp4", parsed.Host)
	if err != nil {
		t.Fatal(err)
	}
	if address.IP.String() != "127.0.0.1" || address.Port == 0 {
		t.Fatalf("listener = %s, want dynamic IPv4 loopback", address)
	}
	second, _ := startSecurityTestHost(t, http.NotFoundHandler())
	if second.URL() == host.URL() {
		t.Fatalf("two dynamic listeners selected the same live address %s", host.URL())
	}
	if second.csrfToken == host.csrfToken {
		t.Fatal("independent host instances reused a CSRF token")
	}
}

func TestHostAndOriginGuards(t *testing.T) {
	host, client := startSecurityTestHost(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	expectedHost := strings.TrimPrefix(host.URL(), "http://")

	response, _ := request(t, client, http.MethodGet, host.URL(), "foreign.example", "", "")
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign Host status = %d", response.StatusCode)
	}
	response, _ = request(t, client, http.MethodGet, host.URL(), expectedHost, "https://foreign.example", "")
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign Origin status = %d", response.StatusCode)
	}
	response, _ = request(t, client, http.MethodGet, host.URL(), expectedHost, "null", "")
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("null Origin status = %d", response.StatusCode)
	}
	for _, origin := range []string{"", host.URL()} {
		response, _ = request(t, client, http.MethodGet, host.URL(), expectedHost, origin, "")
		if response.StatusCode != http.StatusNoContent {
			t.Fatalf("same-origin safe request status = %d", response.StatusCode)
		}
	}
}

func TestMutationRequiresExactOriginAndCSRF(t *testing.T) {
	var reached atomic.Bool
	host, client := startSecurityTestHost(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		reached.Store(true)
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	for _, test := range []struct {
		name   string
		origin string
		token  string
	}{
		{name: "missing both"},
		{name: "missing token", origin: host.URL()},
		{name: "foreign origin", origin: "https://foreign.example", token: host.csrfToken},
		{name: "null origin", origin: "null", token: host.csrfToken},
		{name: "wrong token", origin: host.URL(), token: "wrong"},
	} {
		t.Run(test.name, func(t *testing.T) {
			reached.Store(false)
			response, body := request(t, client, http.MethodPost, host.URL(), "", test.origin, test.token)
			if response.StatusCode != http.StatusForbidden || reached.Load() {
				t.Fatalf("status=%d reached=%v", response.StatusCode, reached.Load())
			}
			if strings.Contains(body, host.csrfToken) {
				t.Fatal("CSRF token leaked in rejection body")
			}
		})
	}
	reached.Store(false)
	response, body := request(t, client, http.MethodPost, host.URL(), "", host.URL(), host.csrfToken)
	if response.StatusCode != http.StatusMethodNotAllowed || !reached.Load() {
		t.Fatalf("valid guarded mutation status=%d reached=%v body=%q", response.StatusCode, reached.Load(), body)
	}
}

func TestSecurityHeadersAndNoCORSWildcard(t *testing.T) {
	host, client := startSecurityTestHost(t, http.NotFoundHandler())
	response, _ := request(t, client, http.MethodGet, host.URL(), "", "", "")
	expected := map[string]string{
		"Content-Security-Policy":      contentSecurityPolicy,
		"X-Content-Type-Options":       "nosniff",
		"Referrer-Policy":              "no-referrer",
		"X-Frame-Options":              "DENY",
		"Cross-Origin-Resource-Policy": "same-origin",
		"Cache-Control":                "no-store",
	}
	for name, value := range expected {
		if got := response.Header.Get(name); got != value {
			t.Errorf("%s = %q, want %q", name, got, value)
		}
	}
	if got := response.Header.Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("unexpected CORS header %q", got)
	}
}

func TestContextCancellationStopsAndReleasesPort(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	host, err := StartHost(ctx, http.NotFoundHandler())
	if err != nil {
		t.Fatal(err)
	}
	address := strings.TrimPrefix(host.URL(), "http://")
	cancel()
	select {
	case <-host.done:
	case <-time.After(2 * time.Second):
		t.Fatal("host did not stop after context cancellation")
	}
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		t.Fatalf("released address cannot be rebound: %v", err)
	}
	listener.Close()
}
