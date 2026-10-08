package tools

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/falcon-mcp/internal/config"
	"github.com/lcleveland/falcon-mcp/internal/falcon"
)

// session is the status tests' server: a made-up probe result and no
// group filter.
func session(t *testing.T, tokenStatus int, h http.HandlerFunc) *mcp.ClientSession {
	t.Helper()
	probes := &falcon.Probes{Results: map[string]falcon.ProbeResult{
		"Hosts:read":  {State: falcon.ProbeOK},
		"Alerts:read": {State: falcon.ProbeMissing, Status: 403},
	}}
	return sessionWith(t, &config.Config{}, probes, tokenStatus, h)
}

func call(t *testing.T, cs *mcp.ClientSession, name string) (map[string]any, bool) {
	t.Helper()
	out, isErr, _ := callTool(t, cs, name, nil)
	return out, isErr
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
	if p, _ := out["probe"].(map[string]any); p["Alerts:read"].(map[string]any)["state"] != falcon.ProbeMissing || p["Hosts:read"].(map[string]any)["state"] != falcon.ProbeOK {
		t.Errorf("probe = %v", out["probe"])
	}
	if tl, _ := out["tools"].(map[string]any); tl["falcon_alert"] != nil || tl["falcon_host"] == nil || tl["falcon_status"] == nil {
		t.Errorf("tools = %v", out["tools"])
	}
	if g, _ := out["tool_groups"].([]any); len(g) != len(config.Groups) {
		t.Errorf("tool_groups = %v", out["tool_groups"])
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

	// Any other failure of the read is a tool error.
	cs = session(t, http.StatusCreated, func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusBadGateway) })
	if out, isErr = call(t, cs, "falcon_status"); !isErr || out["api_reachable"] != false {
		t.Errorf("5xx status = %v, isErr = %t", out, isErr)
	}

	// Rejected credentials are a tool error, not a protocol error.
	cs = session(t, http.StatusForbidden, nil)
	out, isErr = call(t, cs, "falcon_status")
	if !isErr || out["authenticated"] != false || !strings.Contains(out["detail"].(string), "IP allowlist") {
		t.Errorf("rejected status = %v, isErr = %t", out, isErr)
	}
}
