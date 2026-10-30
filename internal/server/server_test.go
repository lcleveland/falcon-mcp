package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lcleveland/falcon-mcp/internal/config"
	"github.com/lcleveland/falcon-mcp/internal/falcon"
)

// fake is a Falcon whose token endpoint answers tokenStatus (0 closes the
// server, for a network error) and whose API answers 200.
func fake(t *testing.T, tokenStatus int) (*falcon.Client, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path == "/oauth2/token" {
			w.WriteHeader(tokenStatus)
			io.WriteString(w, `{"access_token":"tok","expires_in":1799}`)
			return
		}
		io.WriteString(w, `{}`)
	}))
	t.Cleanup(srv.Close)
	url := srv.URL
	if tokenStatus == 0 {
		srv.Close()
	}
	return falcon.New("us-1", url, "id", "secret", nil, nil), &calls
}

var discard = slog.New(slog.DiscardHandler)

func TestProbeAtStartup(t *testing.T) {
	ctx := context.Background()
	defer func(d time.Duration) { tokenRetry = d }(tokenRetry)
	tokenRetry = 0 // no retries here; TestProbeRetriesToken covers them

	c, _ := fake(t, http.StatusCreated)
	p, err := Probe(ctx, &config.Config{}, c, discard)
	if err != nil || p.Results["Hosts:read"].State != falcon.ProbeOK || p.Note != "" {
		t.Errorf("probe: %+v, %v", p, err)
	}

	for _, code := range []int{http.StatusUnauthorized, http.StatusForbidden} {
		c, _ := fake(t, code)
		if _, err := Probe(ctx, &config.Config{}, c, discard); err == nil {
			t.Errorf("token %d: server should not start", code)
		}
	}

	for _, code := range []int{0, http.StatusBadGateway} { // network error, 5xx
		c, _ := fake(t, code)
		p, err := Probe(ctx, &config.Config{}, c, discard)
		if err != nil || len(p.Results) != 0 || !strings.Contains(p.Note, "Restart") || !p.Allows("Alerts:write") {
			t.Errorf("token %d: should degrade: %+v, %v", code, p, err)
		}
	}

	c, calls := fake(t, http.StatusUnauthorized)
	p, err = Probe(ctx, &config.Config{NoProbe: true}, c, discard)
	if err != nil || calls.Load() != 0 || len(p.Results) != 0 || !p.Allows("Alerts:read") {
		t.Errorf("--no-probe: %+v, %v, %d calls", p, err, calls.Load())
	}
}

// A token that fails at first (the network not up yet) is retried, and the
// probe then runs.
func TestProbeRetriesToken(t *testing.T) {
	var tokens atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			if tokens.Add(1) == 1 {
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			w.WriteHeader(http.StatusCreated)
			io.WriteString(w, `{"access_token":"tok","expires_in":1799}`)
			return
		}
		io.WriteString(w, `{}`)
	}))
	defer srv.Close()
	c := falcon.New("us-1", srv.URL, "id", "secret", nil, nil)
	p, err := Probe(context.Background(), &config.Config{}, c, discard)
	if err != nil || p.Note != "" || p.Results["Hosts:read"].State != falcon.ProbeOK || tokens.Load() != 2 {
		t.Errorf("probe after retry: %+v, %v, %d token calls", p, err, tokens.Load())
	}
}
