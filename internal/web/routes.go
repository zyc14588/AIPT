package web

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/zyc14588/AIPT/internal/config"
)

var ErrStaticAsset = errors.New("AIPT_WEB_STATIC_ASSET_FAILED")

// Snapshot composes the exact six-panel dashboard from the shared Config and
// static B007 capability truth.
func Snapshot(validated *config.Config) (Dashboard, error) {
	configPanel, healthPanel, err := ConfigHealth(validated)
	if err != nil {
		return Dashboard{}, err
	}
	queue, run, statusTable, report := Capabilities()
	return Dashboard{
		Schema:      DashboardSchema,
		Config:      configPanel,
		Health:      healthPanel,
		Queue:       queue,
		Run:         run,
		StatusTable: statusTable,
		Report:      report,
	}, nil
}

// NewHandler builds the complete fixed read-only router. The six panels share
// one dashboard endpoint; there is no mutation, queue, run, or report route.
func NewHandler(validated *config.Config) (http.Handler, error) {
	snapshot, err := Snapshot(validated)
	if err != nil {
		return nil, err
	}
	dashboardJSON, err := json.Marshal(snapshot)
	if err != nil {
		return nil, ErrStaticAsset
	}
	healthJSON, err := json.Marshal(struct {
		Schema           string `json:"schema"`
		ServingStatus    string `json:"serving_status"`
		RuntimeReadiness string `json:"runtime_readiness"`
	}{
		Schema:           "aipt.web-health/v1",
		ServingStatus:    snapshot.Health.ServingStatus,
		RuntimeReadiness: snapshot.Health.RuntimeReadiness,
	})
	if err != nil {
		return nil, ErrStaticAsset
	}
	indexHTML, err := staticAssets.ReadFile("static/index.html")
	if err != nil {
		return nil, ErrStaticAsset
	}
	applicationJS, err := staticAssets.ReadFile("static/app.js")
	if err != nil {
		return nil, ErrStaticAsset
	}
	stylesCSS, err := staticAssets.ReadFile("static/styles.css")
	if err != nil {
		return nil, ErrStaticAsset
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/":
			serveReadOnly(w, r, "text/html; charset=utf-8", indexHTML)
		case "/assets/app.js":
			serveReadOnly(w, r, "text/javascript; charset=utf-8", applicationJS)
		case "/assets/styles.css":
			serveReadOnly(w, r, "text/css; charset=utf-8", stylesCSS)
		case "/healthz":
			serveReadOnly(w, r, "application/json; charset=utf-8", healthJSON)
		case "/api/v1/dashboard":
			serveReadOnly(w, r, "application/json; charset=utf-8", dashboardJSON)
		default:
			http.Error(w, "not found", http.StatusNotFound)
		}
	}), nil
}

func serveReadOnly(w http.ResponseWriter, r *http.Request, contentType string, body []byte) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.Header().Set("Allow", "GET, HEAD")
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Del("Content-Length")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(body)
	}
}

// Start builds the fixed router and starts the secured dynamic loopback Host.
func Start(ctx context.Context, validated *config.Config) (*Host, error) {
	handler, err := NewHandler(validated)
	if err != nil {
		return nil, err
	}
	return StartHost(ctx, handler)
}
