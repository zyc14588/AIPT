package web

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRoutesServeStrictDashboardHealthAndEmbeddedAssets(t *testing.T) {
	handler, err := NewHandler(webTestConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		path        string
		contentType string
		contains    string
	}{
		{"/", "text/html; charset=utf-8", "id=\"aipt-dashboard\""},
		{"/assets/app.js", "text/javascript; charset=utf-8", "aipt.web-dashboard/v1"},
		{"/assets/styles.css", "text/css; charset=utf-8", "--background: #11161b"},
		{"/healthz", "application/json; charset=utf-8", "NOT_ASSERTED"},
		{"/api/v1/dashboard", "application/json; charset=utf-8", "IMPLEMENTED_LIBRARY_ONLY"},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodGet, test.path, nil)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK || response.Header().Get("Content-Type") != test.contentType {
				t.Fatalf("status/type = %d/%q", response.Code, response.Header().Get("Content-Type"))
			}
			if !strings.Contains(response.Body.String(), test.contains) {
				t.Fatalf("response body misses %q", test.contains)
			}
			if response.Header().Get("Cache-Control") != "no-store" {
				t.Fatal("route is not no-store")
			}
			head := httptest.NewRequest(http.MethodHead, test.path, nil)
			headResponse := httptest.NewRecorder()
			handler.ServeHTTP(headResponse, head)
			if headResponse.Code != http.StatusOK || headResponse.Body.Len() != 0 {
				t.Fatalf("HEAD status/body = %d/%d", headResponse.Code, headResponse.Body.Len())
			}
			if headResponse.Header().Get("Content-Length") != response.Header().Get("Content-Length") {
				t.Fatal("HEAD Content-Length differs from GET")
			}
		})
	}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/dashboard", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	var snapshot Dashboard
	if err := json.Unmarshal(response.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Schema != DashboardSchema || snapshot.Queue.Items == nil || snapshot.StatusTable.Seats == nil {
		t.Fatalf("strict snapshot drifted: %#v", snapshot)
	}
}

func TestRoutesRejectUnknownPathsAndEveryMutation(t *testing.T) {
	handler, err := NewHandler(webTestConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/missing", "/api/v1/dashboard/", "/assets/../static/index.html", "/queue", "/run", "/report"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
		if response.Code != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, response.Code)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(method, "/api/v1/dashboard", nil))
		body, _ := io.ReadAll(response.Result().Body)
		if response.Code != http.StatusMethodNotAllowed || !strings.Contains(string(body), "method not allowed") {
			t.Errorf("%s dashboard = %d/%q, want 405", method, response.Code, body)
		}
	}
}

func TestSnapshotRejectsNilConfig(t *testing.T) {
	if _, err := Snapshot(nil); err == nil {
		t.Fatal("Snapshot(nil) succeeded")
	}
}

func TestRealRouterValidGuardedMutationReachesMethodNotAllowed(t *testing.T) {
	handler, err := NewHandler(webTestConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	host, client := startSecurityTestHost(t, handler)
	response, body := request(
		t,
		client,
		http.MethodPost,
		host.URL()+"/api/v1/dashboard",
		"",
		host.URL(),
		host.csrfToken,
	)
	if response.StatusCode != http.StatusMethodNotAllowed || !strings.Contains(body, "method not allowed") {
		t.Fatalf("valid guarded mutation = %d/%q, want router 405", response.StatusCode, body)
	}
}
