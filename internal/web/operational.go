package web

import (
	"context"
	"embed"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/zyc14588/AIPT/internal/config"
	"github.com/zyc14588/AIPT/internal/runcontrol"
)

//go:embed operational/index.html operational/controls.js operational/controls.css
var operationalAssets embed.FS

type operationalSession struct {
	origin string
	token  string
}
type operationalHandler struct {
	config  ConfigPanel
	service *runcontrol.Service
	session atomic.Pointer[operationalSession]
}

type OperationalDashboard struct {
	Schema  string              `json:"schema"`
	Config  ConfigPanel         `json:"config"`
	Health  HealthPanel         `json:"health"`
	Control runcontrol.Snapshot `json:"control"`
}

// StartOperational shares exactly one Service with stdio RPC, while reusing
// the accepted fixed IPv4 loopback Host/Origin/CSRF/CSP policy.
func StartOperational(ctx context.Context, validated *config.Config, service *runcontrol.Service) (*Host, error) {
	if service == nil {
		return nil, ErrHostInvalidHandler
	}
	projected, _, err := ConfigHealth(validated)
	if err != nil {
		return nil, err
	}
	handler := &operationalHandler{config: projected, service: service}
	host, err := StartHost(ctx, handler)
	if err != nil {
		return nil, err
	}
	// StartHost may already receive requests. Until this atomic publication,
	// every route is unavailable; no empty/default security token is accepted.
	handler.session.Store(&operationalSession{origin: host.url, token: host.csrfToken})
	return host, nil
}

func (h *operationalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	session := h.session.Load()
	if session == nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	if r.URL.RawQuery != "" {
		http.NotFound(w, r)
		return
	}
	if r.URL.Path == "/api/v1/control" {
		h.command(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if site := r.Header.Values("Sec-Fetch-Site"); len(site) > 1 || (len(site) == 1 && site[0] != "same-origin" && site[0] != "none") {
		http.Error(w, "forbidden request", http.StatusForbidden)
		return
	}
	switch r.URL.Path {
	case "/", "/assets/controls.js", "/assets/controls.css":
		name, kind := "operational/index.html", "text/html; charset=utf-8"
		if r.URL.Path == "/assets/controls.js" {
			name = "operational/controls.js"
			kind = "text/javascript; charset=utf-8"
		}
		if r.URL.Path == "/assets/controls.css" {
			name = "operational/controls.css"
			kind = "text/css; charset=utf-8"
		}
		data, err := operationalAssets.ReadFile(name)
		if err != nil {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", kind)
		if r.Method == http.MethodGet {
			_, _ = w.Write(data)
		}
	case "/api/v1/session":
		// Cross-origin requests were rejected by StartHost; fetch-site is checked
		// above as defense in depth. The token is in-memory and never in a URL/log.
		writeOperationalJSON(w, r, http.StatusOK, struct {
			Schema string `json:"schema"`
			Token  string `json:"csrf_token"`
		}{"aipt.web-session/v1", session.token})
	case "/healthz":
		writeOperationalJSON(w, r, http.StatusOK, HealthPanel{ServingStatus: StatusServing, RuntimeReadiness: ReadinessNotAsserted})
	case "/api/v1/dashboard":
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		snapshot, err := h.service.Snapshot(ctx, 100)
		if err != nil {
			writeOperationalJSON(w, r, http.StatusServiceUnavailable, map[string]string{"error": runcontrol.PublicCode(err)})
			return
		}
		writeOperationalJSON(w, r, http.StatusOK, OperationalDashboard{Schema: "aipt.web-operational/v1", Config: h.config, Health: HealthPanel{ServingStatus: StatusServing, RuntimeReadiness: ReadinessNotAsserted}, Control: snapshot})
	default:
		http.NotFound(w, r)
	}
}

func (h *operationalHandler) command(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	kind, parameters, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || kind != "application/json" || len(parameters) > 1 || (len(parameters) == 1 && !strings.EqualFold(parameters["charset"], "utf-8")) {
		http.Error(w, "unsupported content type", http.StatusUnsupportedMediaType)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, runcontrol.MaxRequestBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "invalid request", http.StatusRequestEntityTooLarge)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	response := h.service.Respond(ctx, body)
	code := http.StatusOK
	if response.Error != nil {
		code = http.StatusConflict
		if response.Error.Code == -32600 || response.Error.Code == -32602 {
			code = http.StatusBadRequest
		}
		if response.Error.Code == -32601 {
			code = http.StatusNotFound
		}
	}
	writeOperationalJSON(w, r, code, response)
}
func writeOperationalJSON(w http.ResponseWriter, r *http.Request, status int, value any) {
	data, err := json.Marshal(value)
	if err != nil {
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = w.Write(append(data, '\n'))
	}
}
