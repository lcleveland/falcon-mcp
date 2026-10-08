//go:build live

package falcon

// Run with: go test -tags live -run Live ./internal/falcon
// It reads the verification API client from ~/.config/falcon-mcp/ and
// asserts that no probe route is a 404 or a 400. It reports only broken
// routes, never which scopes pass, response bodies or tenant details.

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLiveProbeRoutes(t *testing.T) {
	home, _ := os.UserHomeDir()
	read := func(name string) string {
		b, err := os.ReadFile(filepath.Join(home, ".config/falcon-mcp", name))
		if err != nil {
			t.Skip("no verification credentials: ", err)
		}
		return strings.TrimSpace(string(b))
	}
	c := New("", "", read("client-id"), read("client-secret"), nil, nil)
	// Without a token every probe fails before reaching its route.
	if _, err := c.Authenticate(context.Background()); err != nil {
		t.Fatal(err)
	}
	p := c.Probe(context.Background(), ProbeDeadline)
	for scope, r := range p.Results {
		// Which scopes pass would reveal the tenant's licences: report only
		// broken routes. A route that 404s or rejects its own query can
		// never pass.
		if r.Status == http.StatusNotFound || r.Status == http.StatusBadRequest {
			t.Errorf("%s: probe route %s answered %d", scope, probes[scope].op, r.Status)
		}
	}
}
