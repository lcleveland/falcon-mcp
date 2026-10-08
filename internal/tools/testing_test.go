package tools

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/falcon-mcp/internal/config"
	"github.com/lcleveland/falcon-mcp/internal/falcon"
)

// sessionWith starts a fake Falcon (token endpoint answering tokenStatus,
// everything else h) and an in-memory MCP client/server pair.
func sessionWith(t *testing.T, cfg *config.Config, probes *falcon.Probes, tokenStatus int, h http.HandlerFunc) *mcp.ClientSession {
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
	Register(s, Deps{Client: c, Config: cfg, Probes: probes})
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

// request is one call the fake Falcon received.
type request struct {
	Method, Path, Query, Body string
}

// fixtures serves testdata files by route path and records each request.
type fixtures struct {
	mu     sync.Mutex
	routes map[string]string // path -> testdata file
	seen   []request
}

func (f *fixtures) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.seen = append(f.seen, request{r.Method, r.URL.Path, r.URL.RawQuery, string(b)})
	file, ok := f.routes[r.URL.Path]
	f.mu.Unlock()
	if !ok {
		w.WriteHeader(http.StatusNotFound)
		io.WriteString(w, `{"errors":[{"code":404,"message":"no fixture"}]}`)
		return
	}
	body, err := os.ReadFile(filepath.Join("testdata", file))
	if err != nil {
		panic(err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(body)
}

func (f *fixtures) requests() []request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]request(nil), f.seen...)
}

func (f *fixtures) reset() { f.mu.Lock(); f.seen = nil; f.mu.Unlock() }

// callTool invokes a tool and decodes its structured result, also returning
// IsError and the first text content.
func callTool(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (map[string]any, bool, string) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	text := ""
	if len(res.Content) > 0 {
		if tc, ok := res.Content[0].(*mcp.TextContent); ok {
			text = tc.Text
		}
	}
	var out map[string]any
	if res.StructuredContent != nil {
		b, _ := json.Marshal(res.StructuredContent)
		json.Unmarshal(b, &out)
	}
	return out, res.IsError, text
}

func listTools(t *testing.T, cs *mcp.ClientSession) map[string]*mcp.Tool {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]*mcp.Tool{}
	for _, tl := range res.Tools {
		m[tl.Name] = tl
	}
	return m
}
