package tools

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/falcon-mcp/internal/config"
	"github.com/lcleveland/falcon-mcp/internal/falcon"
)

// session starts a fake Falcon (token endpoint answering tokenStatus, plus h)
// and an in-memory MCP client/server pair.
func session(t *testing.T, tokenStatus int, h http.HandlerFunc) *mcp.ClientSession {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			w.WriteHeader(tokenStatus)
			io.WriteString(w, `{"access_token":"tok","expires_in":1799}`)
			return
		}
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	c := falcon.New("eu-1", srv.URL, "id", "secret", srv.Client(), nil)
	c.RetryDelay = 0

	s := mcp.NewServer(&mcp.Implementation{Name: "test"}, nil)
	Register(s, Deps{Client: c, Config: &config.Config{}})
	st, ct := mcp.NewInMemoryTransports()
	ctx := context.Background()
	if _, err := s.Connect(ctx, st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "client"}, nil).Connect(ctx, ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func call(t *testing.T, cs *mcp.ClientSession, name string) (map[string]any, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var out map[string]any
	b, _ := json.Marshal(res.StructuredContent)
	json.Unmarshal(b, &out)
	return out, res.IsError
}

func TestStatus(t *testing.T) {
	var query string
	cs := session(t, http.StatusCreated, func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.Path + "?" + r.URL.RawQuery
		w.Header().Set("X-RateLimit-Limit", "6000")
		w.Header().Set("X-RateLimit-Remaining", "5999")
		io.WriteString(w, `{"resources":["a"]}`)
	})
	out, isErr := call(t, cs, "falcon_status")
	if isErr || out["authenticated"] != true || out["api_reachable"] != true || out["cloud"] != "eu-1" || out["token_expires"] == nil {
		t.Fatalf("status = %v", out)
	}
	if rl, _ := out["rate_limit"].(map[string]any); rl["limit"] != 6000.0 || rl["remaining"] != 5999.0 {
		t.Errorf("rate_limit = %v", out["rate_limit"])
	}
	if query != "/devices/queries/devices/v1?limit=1" {
		t.Errorf("probe = %s", query)
	}

	// A missing scope on the cheap read is not a status failure.
	cs = session(t, http.StatusCreated, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Limit", "6000")
		w.Header().Set("X-RateLimit-Remaining", "10")
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, `{"errors":[{"message":"access denied, scope not permitted"}]}`)
	})
	out, isErr = call(t, cs, "falcon_status")
	if isErr || out["authenticated"] != true || out["api_reachable"] != false || !strings.Contains(out["detail"].(string), "missing scope") || out["rate_limit"] == nil {
		t.Errorf("forbidden status = %v", out)
	}

	// Rejected credentials are a tool error, not a protocol error.
	cs = session(t, http.StatusForbidden, nil)
	out, isErr = call(t, cs, "falcon_status")
	if !isErr || out["authenticated"] != false || !strings.Contains(out["detail"].(string), "IP allowlist") {
		t.Errorf("rejected status = %v, isErr = %t", out, isErr)
	}
}
