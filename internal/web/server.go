package web

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"sync"
	"time"
)

const (
	loopbackListenAddress      = "127.0.0.1:0"
	defaultHostShutdownTimeout = 5 * time.Second
)

var (
	ErrHostInvalidHandler  = errors.New("AIPT_WEB_INVALID_HANDLER")
	ErrHostInvalidListener = errors.New("AIPT_WEB_INVALID_LISTENER")
	ErrHostTokenGeneration = errors.New("AIPT_WEB_CSRF_GENERATION_FAILED")
)

// Host owns one process-local HTTP listener. Its bind and security policy are
// not configurable: B007 can only listen on an OS-selected IPv4 loopback port.
type Host struct {
	listener  net.Listener
	server    *http.Server
	url       string
	csrfToken string
	done      chan struct{}

	stopOnce sync.Once
	stopErr  error
}

// StartHost starts handler on exactly tcp4 127.0.0.1:0. It validates the
// selected listener before serving and installs Host, Origin, CSRF, and
// response-header guards around every route.
func StartHost(ctx context.Context, handler http.Handler) (*Host, error) {
	if handler == nil {
		return nil, ErrHostInvalidHandler
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	listener, err := net.Listen("tcp4", loopbackListenAddress)
	if err != nil {
		return nil, ErrHostInvalidListener
	}
	tcpAddress, ok := listener.Addr().(*net.TCPAddr)
	if !ok || tcpAddress.IP == nil || tcpAddress.IP.To4() == nil || !tcpAddress.IP.Equal(net.IPv4(127, 0, 0, 1)) || tcpAddress.Port == 0 {
		_ = listener.Close()
		return nil, ErrHostInvalidListener
	}

	tokenBytes := make([]byte, 32)
	if _, err := rand.Read(tokenBytes); err != nil {
		_ = listener.Close()
		return nil, ErrHostTokenGeneration
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes)
	hostPort := listener.Addr().String()
	host := &Host{
		listener:  listener,
		url:       "http://" + hostPort,
		csrfToken: token,
		done:      make(chan struct{}),
	}
	host.server = &http.Server{
		Handler:           secureHandler(hostPort, host.url, token, handler),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       30 * time.Second,
		MaxHeaderBytes:    16 * 1024,
		ErrorLog:          log.New(io.Discard, "", 0),
	}
	go func() {
		defer close(host.done)
		_ = host.server.Serve(listener)
	}()
	go func() {
		select {
		case <-ctx.Done():
			shutdownContext, cancel := context.WithTimeout(context.Background(), defaultHostShutdownTimeout)
			defer cancel()
			_ = host.Stop(shutdownContext)
		case <-host.done:
		}
	}()
	return host, nil
}

// URL returns the diagnostic loopback URL. It never contains the CSRF token.
func (h *Host) URL() string {
	if h == nil {
		return ""
	}
	return h.url
}

// Stop gracefully stops the listener at most once. A failed graceful
// shutdown is followed by a synchronous close so the port is not abandoned.
func (h *Host) Stop(ctx context.Context) error {
	if h == nil {
		return nil
	}
	h.stopOnce.Do(func() {
		h.stopErr = h.server.Shutdown(ctx)
		if h.stopErr != nil {
			_ = h.server.Close()
		}
		<-h.done
	})
	return h.stopErr
}
