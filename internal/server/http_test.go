package server

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/falcon-mcp/internal/config"
	"github.com/lcleveland/falcon-mcp/internal/falcon"
)

func newHTTP(t *testing.T, cfg *config.Config) *httptest.Server {
	t.Helper()
	cfg.Path = "/mcp"
	c, _ := fake(t, http.StatusCreated)
	s, _, stop := New(cfg, c, nil, discard)
	t.Cleanup(stop)
	ts := httptest.NewServer(Handler(cfg, s, discard))
	t.Cleanup(ts.Close)
	return ts
}

type bearer struct {
	tok  string
	next http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.tok)
	return b.next.RoundTrip(r)
}

func connect(url, tok string) (*mcp.ClientSession, error) {
	hc := http.DefaultClient
	if tok != "" {
		hc = &http.Client{Transport: bearer{tok, http.DefaultTransport}}
	}
	return mcp.NewClient(&mcp.Implementation{Name: "t"}, nil).Connect(context.Background(),
		&mcp.StreamableClientTransport{Endpoint: url + "/mcp", HTTPClient: hc}, nil)
}

func TestHTTPToolsAndHealthz(t *testing.T) {
	ts := newHTTP(t, &config.Config{})
	cs, err := connect(ts.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	defer cs.Close()
	if res, err := cs.ListTools(context.Background(), nil); err != nil || len(res.Tools) < 5 {
		t.Fatalf("tools: %v %v", res, err)
	}
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(b), `"ok"`) {
		t.Errorf("healthz: %d %s", resp.StatusCode, b)
	}
}

func TestHTTPBearer(t *testing.T) {
	ts := newHTTP(t, &config.Config{HTTPAuthToken: "right-token"})
	for _, tok := range []string{"", "wrong-token"} {
		if cs, err := connect(ts.URL, tok); err == nil {
			cs.Close()
			t.Errorf("token %q accepted", tok)
		}
	}
	cs, err := connect(ts.URL, "right-token")
	if err != nil {
		t.Fatal(err)
	}
	cs.Close()
	// healthz stays open for liveness probes.
	if resp, err := http.Get(ts.URL + "/healthz"); err != nil || resp.StatusCode != 200 {
		t.Errorf("healthz behind auth: %v %v", resp, err)
	}
}

// A search still polling Falcon when the server shuts down has its job
// stopped, the way main shuts down: drain HTTP, then stop the tools.
func TestHTTPShutdownStopsNGSIEMJobs(t *testing.T) {
	var (
		mu      sync.Mutex
		stopped []string
	)
	started := make(chan struct{}, 1)
	falconAPI := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/oauth2/token":
			w.WriteHeader(http.StatusCreated)
			io.WriteString(w, `{"access_token":"tok","expires_in":1799}`)
		case r.Method == http.MethodPost:
			io.WriteString(w, `{"id":"job-1"}`)
		case r.Method == http.MethodGet:
			select {
			case started <- struct{}{}:
			default:
			}
			io.WriteString(w, `{"done":false,"metaData":{}}`)
		case r.Method == http.MethodDelete:
			mu.Lock()
			stopped = append(stopped, r.URL.Path)
			mu.Unlock()
		}
	}))
	defer falconAPI.Close()
	cfg := &config.Config{Path: "/mcp", Allow: map[string]bool{}}
	s, _, stop := New(cfg, falcon.New("us-1", falconAPI.URL, "id", "secret", nil, nil), nil, discard)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	served := make(chan error, 1)
	go func() { err := ServeHTTP(ctx, ln, cfg, s, discard); stop(); served <- err }()

	cs, err := connect("http://"+ln.Addr().String(), "")
	if err != nil {
		t.Fatal(err)
	}
	go cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "falcon_ngsiem", Arguments: map[string]any{"action": "search", "query": "x"}})
	<-started
	cancel()
	select {
	case err := <-served:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server did not shut down")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(stopped) == 0 {
		t.Error("NGSIEM job not stopped by the time shutdown returned")
	}
}
