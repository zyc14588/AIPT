package web

import (
	"context"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestLiveLoopbackSmoke(t *testing.T) {
	host, err := Start(context.Background(), webTestConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Timeout: 2 * time.Second}
	for _, path := range []string{"/", "/healthz", "/api/v1/dashboard"} {
		response, err := client.Get(host.URL() + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		body, err := io.ReadAll(response.Body)
		response.Body.Close()
		if err != nil || response.StatusCode != http.StatusOK || len(body) == 0 {
			t.Fatalf("GET %s = status %d, bytes %d, err %v", path, response.StatusCode, len(body), err)
		}
		lower := strings.ToLower(string(body))
		for _, forbidden := range []string{"web_unique_user", "web_unique_password", "\"dsn\""} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("GET %s leaked %q", path, forbidden)
			}
		}
	}

	foreign, _ := http.NewRequest(http.MethodGet, host.URL()+"/api/v1/dashboard", nil)
	foreign.Host = "foreign.example"
	response, err := client.Do(foreign)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign Host = %d, want 403", response.StatusCode)
	}

	foreignOrigin, _ := http.NewRequest(http.MethodGet, host.URL()+"/api/v1/dashboard", nil)
	foreignOrigin.Header.Set("Origin", "https://foreign.example")
	response, err = client.Do(foreignOrigin)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusForbidden {
		t.Fatalf("foreign Origin = %d, want 403", response.StatusCode)
	}

	address := strings.TrimPrefix(host.URL(), "http://")
	shutdownContext, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := host.Stop(shutdownContext); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", address)
	if err != nil {
		t.Fatalf("stopped dynamic port was not released: %v", err)
	}
	listener.Close()
}
