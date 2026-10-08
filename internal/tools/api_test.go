package tools

import (
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/lcleveland/falcon-mcp/internal/config"
	"github.com/lcleveland/falcon-mcp/internal/falcon"
)

// Every write op in the generated table is classified for falcon_api:
// owned by a typed action (which keeps its rails), or in apiWrites with a
// capability or never. A regenerated table with a new write fails here.
func TestEveryWriteOpIsClassified(t *testing.T) {
	rs := apiRoutes()
	for id, op := range falcon.All() {
		if !op.Write {
			continue
		}
		r, ok := rs[id]
		switch {
		case !ok || (r.tool == "" && r.capability == ""):
			t.Errorf("%s: unclassified write; add it to apiWrites", id)
		case r.tool == "" && r.capability != never && !slices.Contains(config.Capabilities, r.capability):
			t.Errorf("%s: unknown capability %q", id, r.capability)
		}
	}
	owned := map[string]bool{}
	for _, tl := range Tools() {
		for _, a := range tl.Actions {
			if a.Kind == Write {
				owned[a.Op] = true
			}
		}
	}
	for id := range apiWrites {
		if op, ok := falcon.Lookup(id); !ok || !op.Write || owned[id] {
			t.Errorf("apiWrites[%s]: want a write op no typed action sends", id)
		}
	}
}

// A concrete path must name one op per method, or a write could be routed
// as a read.
func TestNoAmbiguousRoutes(t *testing.T) {
	type entry struct{ id, method, path string }
	var all []entry
	for id, op := range falcon.All() {
		all = append(all, entry{id, op.Method, op.Path})
	}
	for i, a := range all {
		for _, b := range all[i+1:] {
			if a.method == b.method && overlap(a.path, b.path) {
				t.Errorf("%s and %s both match some %s path (%s, %s)", a.id, b.id, a.method, a.path, b.path)
			}
		}
	}
}

func overlap(a, b string) bool {
	as, bs := strings.Split(a, "/"), strings.Split(b, "/")
	if len(as) != len(bs) {
		return false
	}
	for i := range as {
		if as[i] != bs[i] && !strings.HasPrefix(as[i], "{") && !strings.HasPrefix(bs[i], "{") {
			return false
		}
	}
	return true
}

func TestAPIRefusals(t *testing.T) {
	f := &fakeWrites{}
	call, _ := writeSession(t, config.Capabilities, 0, f)
	for _, c := range []struct {
		args map[string]any
		want string
	}{
		{map[string]any{"op": "BatchActiveResponderCmd", "reason": "x", "body": map[string]any{}}, "never"},
		{map[string]any{"method": "PATCH", "path": "/quarantine/queries/quarantined-files/v1", "reason": "x"}, "never"},
		{map[string]any{"op": "NoSuchOp", "reason": "x"}, "not in the op table"},
		{map[string]any{"method": "POST", "path": "/devices/entities/devices-actions/v9", "reason": "x"}, "cannot classify"},
		{map[string]any{"method": "DELETE", "path": "/anything/v1", "reason": "x"}, "cannot classify"},
		{map[string]any{"op": "PerformActionV2", "reason": "x"}, "falcon_host"},
		{map[string]any{"method": "PATCH", "path": "/alerts/entities/alerts/v3", "reason": "x"}, "falcon_alert"},
		{map[string]any{"op": "post_graphql", "body": map[string]any{"query": "mutation { x }"}}, "falcon_identity"},
		{map[string]any{"op": "entities_rules_post_v1", "body": map[string]any{}}, "reason is required"},
		{map[string]any{"method": "GET", "path": "/devices/../oauth2/token"}, "path must be"},
		{map[string]any{"method": "GET", "path": "/devices/queries/devices/v1?filter=x"}, "path must be"},
		{map[string]any{"op": "QueryDevicesByFilter", "path": "/devices/queries/devices/v1"}, "op, or method and path"},
	} {
		if _, isErr, text := call("falcon_api", c.args); !isErr || !strings.Contains(text, c.want) {
			t.Errorf("%v: %v %s, want %q", c.args, isErr, text, c.want)
		}
	}
	if w := f.writes(); len(w) != 0 {
		t.Errorf("writes sent: %v", w)
	}
}

func TestAPIWriteNeedsCapability(t *testing.T) {
	f := &fakeWrites{}
	call, _ := writeSession(t, []string{"triage"}, 0, f)
	_, isErr, text := call("falcon_api", map[string]any{"op": "entities_rules_post_v1", "reason": "x", "body": map[string]any{"name": "r"}})
	if !isErr || !strings.Contains(text, "detection-add") {
		t.Errorf("%v %s", isErr, text)
	}
	// RTR reads are gated by rtr-read like their typed action.
	_, isErr, text = call("falcon_api", map[string]any{"op": "RTR_ListFilesV2", "query": map[string]any{"session_id": "s"}})
	if !isErr || !strings.Contains(text, "rtr-read") {
		t.Errorf("%v %s", isErr, text)
	}
	if r := f.requests(); len(r) != 0 {
		t.Errorf("sent: %v", r)
	}
}

func TestAPIWrite(t *testing.T) {
	f := &fakeWrites{replies: map[string]reply{
		"POST /correlation-rules/entities/rules/v1": {http.StatusInternalServerError, `{"errors":[{"message":"boom"}]}`},
	}}
	call, logs := writeSession(t, []string{"detection-add"}, 0, f)
	_, isErr, text := call("falcon_api", map[string]any{"method": "post", "path": "/correlation-rules/entities/rules/v1",
		"reason": "new rule for ticket 7", "body": map[string]any{"name": "r"}, "query": map[string]any{"x": []any{"a", 2.0}}})
	if !isErr || !strings.Contains(text, "HTTP 500") {
		t.Fatalf("%v %s", isErr, text)
	}
	w := f.writes()
	if len(w) != 1 { // never retried
		t.Fatalf("writes: %v", w)
	}
	if w[0].Body != `{"name":"r"}` || w[0].Query != "x=a&x=2" {
		t.Errorf("sent %+v", w[0])
	}
	for _, s := range []string{`"tool":"falcon_api"`, `"op":"entities_rules_post_v1"`, `"capability":"detection-add"`, `"reason":"new rule for ticket 7"`, "falcon write failed"} {
		if !strings.Contains(logs.String(), s) {
			t.Errorf("audit log lacks %s:\n%s", s, logs)
		}
	}
}

func TestAPIRead(t *testing.T) {
	var hits []string
	f := func(w http.ResponseWriter, r *http.Request) {
		hits = append(hits, r.Method+" "+r.URL.Path+"?"+r.URL.RawQuery)
		switch r.URL.Path {
		case "/humio/api/v1/repositories/search-all/queryjobs/j1":
			if len(hits) == 1 { // a read is retried once
				w.WriteHeader(http.StatusBadGateway)
				return
			}
			w.Write([]byte(`{"done":true,"events":[]}`))
		case "/devices/queries/devices/v1":
			w.Write([]byte(`{"meta":{"pagination":{"total":3,"offset":"o2"}},"resources":["a","b"]}`))
		case "/not/in/table/v1":
			w.Write([]byte("a,b\n1,2\n"))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
	probes := &falcon.Probes{Results: map[string]falcon.ProbeResult{"Alerts:read": {State: falcon.ProbeMissing}}}
	cs := sessionWith(t, &config.Config{Allow: map[string]bool{}}, probes, http.StatusCreated, f)

	out, isErr, text := callTool(t, cs, "falcon_api", map[string]any{"op": "GetSearchStatusV1", "path_params": map[string]any{"repository": "search-all", "id": "j1"}})
	if isErr || out["results"].(map[string]any)["done"] != true {
		t.Errorf("by op: %v %s %v", isErr, text, out)
	}
	out, isErr, text = callTool(t, cs, "falcon_api", map[string]any{"method": "GET", "path": "/devices/queries/devices/v1", "query": map[string]any{"limit": 2.0}})
	if isErr || len(out["results"].([]any)) != 2 || out["meta"] == nil {
		t.Errorf("by path: %v %s %v", isErr, text, out)
	}
	out, isErr, text = callTool(t, cs, "falcon_api", map[string]any{"method": "GET", "path": "/not/in/table/v1"})
	if isErr || out["results"] != "a,b\n1,2\n" {
		t.Errorf("untabled GET: %v %s %v", isErr, text, out)
	}
	// The probe hides what it hides from the typed tools.
	_, isErr, text = callTool(t, cs, "falcon_api", map[string]any{"op": "GetQueriesAlertsV2"})
	if !isErr || !strings.Contains(text, "Alerts:read") {
		t.Errorf("probed: %v %s", isErr, text)
	}
	want := []string{
		"GET /humio/api/v1/repositories/search-all/queryjobs/j1?", "GET /humio/api/v1/repositories/search-all/queryjobs/j1?",
		"GET /devices/queries/devices/v1?limit=2", "GET /not/in/table/v1?",
	}
	if !slices.Equal(hits, want) {
		t.Errorf("hits %v", hits)
	}
}
