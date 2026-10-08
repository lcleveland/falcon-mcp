package tools

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/lcleveland/falcon-mcp/internal/config"
)

// fakeWrites answers "METHOD path" with a canned status and body (200 and
// an empty envelope when unlisted) and records every request.
type fakeWrites struct {
	mu      sync.Mutex
	replies map[string]reply
	seen    []request
}

type reply struct {
	status int
	body   string
}

func (f *fakeWrites) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.seen = append(f.seen, request{r.Method, r.URL.Path, r.URL.RawQuery, string(b)})
	rp, ok := f.replies[r.Method+" "+r.URL.Path]
	f.mu.Unlock()
	if !ok {
		rp = reply{http.StatusOK, `{"meta":{"trace_id":"trace-1"},"resources":[]}`}
	}
	w.WriteHeader(rp.status)
	io.WriteString(w, rp.body)
}

func (f *fakeWrites) reset() { f.mu.Lock(); f.seen = nil; f.mu.Unlock() }

func (f *fakeWrites) requests() []request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]request(nil), f.seen...)
}

// writes are the requests that were not reads.
func (f *fakeWrites) writes() []request {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []request
	for _, r := range f.seen {
		if r.Method != http.MethodGet && !(r.Method == http.MethodPost && r.Path == "/devices/entities/devices/v2") {
			out = append(out, r)
		}
	}
	return out
}

func writeSession(t *testing.T, allow []string, maxBulk int, f *fakeWrites) (func(string, map[string]any) (map[string]any, bool, string), *bytes.Buffer) {
	t.Helper()
	cfg := &config.Config{Allow: map[string]bool{}, MaxBulk: cmp.Or(maxBulk, 1000)}
	for _, c := range allow {
		cfg.Allow[c] = true
	}
	var logs bytes.Buffer
	cs := sessionLog(t, cfg, nil, http.StatusCreated, f.ServeHTTP, slog.New(slog.NewJSONHandler(&logs, nil)))
	return func(name string, args map[string]any) (map[string]any, bool, string) {
		t.Helper()
		return callTool(t, cs, name, args)
	}, &logs
}

func TestDisabledCapabilityIsHiddenAndRefused(t *testing.T) {
	f := &fakeWrites{}
	cfg := &config.Config{Allow: map[string]bool{"host-tags": true}}
	cs := sessionWith(t, cfg, nil, http.StatusCreated, f.ServeHTTP)
	tl := listTools(t, cs)

	schema := func(tool string) (actions []string, props map[string]any) {
		b, _ := json.Marshal(tl[tool].InputSchema)
		var s struct {
			Properties map[string]any `json:"properties"`
		}
		json.Unmarshal(b, &s)
		for _, a := range s.Properties["action"].(map[string]any)["enum"].([]any) {
			actions = append(actions, a.(string))
		}
		return actions, s.Properties
	}
	acts, props := schema("falcon_alert")
	if slices.Contains(acts, "update") || props["reason"] != nil || props["confirm"] != nil {
		t.Errorf("falcon_alert with triage off: actions %v, reason %v", acts, props["reason"])
	}
	if !tl["falcon_alert"].Annotations.ReadOnlyHint {
		t.Error("falcon_alert with no writes should be read-only")
	}
	acts, props = schema("falcon_host")
	if slices.Contains(acts, "contain") || !slices.Contains(acts, "add_tags") || props["reason"] == nil {
		t.Errorf("falcon_host with host-tags on, containment off: actions %v", acts)
	}
	if tl["falcon_host"].Annotations.ReadOnlyHint {
		t.Error("falcon_host with a write shown is not read-only")
	}

	for _, c := range []struct{ tool, action string }{{"falcon_alert", "update"}, {"falcon_host", "contain"}} {
		if _, isErr, text := callTool(t, cs, c.tool, map[string]any{"action": c.action, "ids": []string{"x"}, "id": "x", "reason": "r", "confirm": "h"}); !isErr {
			t.Errorf("%s %s with its capability off: %s", c.tool, c.action, text)
		}
	}
	if out, _, _ := callTool(t, cs, "falcon_status", nil); fmt.Sprint(out["capabilities"]) != "[host-tags]" {
		t.Errorf("status capabilities = %v", out["capabilities"])
	}
	// The handler refuses too, whatever reaches it.
	contain := Action{Kind: Write, Capability: "containment", Op: "PerformActionV2", Target: TargetHost, Send: hostAction("contain")}
	if _, err := (Deps{Config: cfg}).write(t.Context(), "falcon_host", contain, Input{ID: "x", Reason: "r", Confirm: "h"}); err == nil || !strings.Contains(err.Error(), "containment") {
		t.Errorf("write with containment off: %v", err)
	}
	if w := f.writes(); len(w) != 0 {
		t.Errorf("sent %+v", w)
	}
}

func TestWriteNeedsReasonAndForwardsIt(t *testing.T) {
	f := &fakeWrites{replies: map[string]reply{
		"PATCH /alerts/entities/alerts/v3": {200, `{"meta":{"trace_id":"trace-77"},"resources":[]}`},
	}}
	call, logs := writeSession(t, []string{"triage"}, 0, f)

	_, isErr, text := call("falcon_alert", map[string]any{"action": "update", "ids": []string{"a:1"}, "params": map[string]any{"update_status": "closed"}, "reason": "  "})
	if !isErr || !strings.Contains(text, "reason") || len(f.writes()) != 0 {
		t.Fatalf("blank reason: %v %s, sent %+v", isErr, text, f.writes())
	}

	out, isErr, text := call("falcon_alert", map[string]any{"action": "update", "ids": []string{"a:1", "a:2"},
		"params": map[string]any{"update_status": "closed", "add_tag": []any{"false_positive", "fp-2"}}, "reason": "benign admin script"})
	if isErr {
		t.Fatal(text)
	}
	w := f.writes()
	if len(w) != 1 {
		t.Fatalf("writes = %+v", w)
	}
	var body struct {
		IDs    []string                       `json:"composite_ids"`
		Params []struct{ Name, Value string } `json:"action_parameters"`
	}
	json.Unmarshal([]byte(w[0].Body), &body)
	got := map[string][]string{}
	for _, p := range body.Params {
		got[p.Name] = append(got[p.Name], p.Value)
	}
	if !slices.Equal(body.IDs, []string{"a:1", "a:2"}) || !slices.Equal(got["update_status"], []string{"closed"}) ||
		!slices.Equal(got["add_tag"], []string{"false_positive", "fp-2"}) || !slices.Equal(got["append_comment"], []string{"benign admin script"}) {
		t.Errorf("body = %s", w[0].Body)
	}
	if out["trace_id"] != "trace-77" {
		t.Errorf("out = %v", out)
	}
	for _, want := range []string{`"msg":"falcon write"`, `"tool":"falcon_alert"`, `"action":"update"`, `"reason":"benign admin script"`, `"trace_id":"trace-77"`, `"a:2"`} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("audit log lacks %s: %s", want, logs)
		}
	}

	// A comment the caller gives carries the reason too.
	f.reset()
	call("falcon_alert", map[string]any{"action": "update", "ids": []string{"a:1"}, "params": map[string]any{"append_comment": "seen on 3 hosts"}, "reason": "triage"})
	if w := f.writes(); len(w) != 1 || !strings.Contains(w[0].Body, `"value":"seen on 3 hosts\n\nReason: triage"`) || strings.Count(w[0].Body, "append_comment") != 1 {
		t.Errorf("writes = %+v", w)
	}

	// Several comments and the reason go as one.
	f.reset()
	call("falcon_alert", map[string]any{"action": "update", "ids": []string{"a:1"}, "params": map[string]any{"append_comment": []any{"one", "two"}}, "reason": "r"})
	if w := f.writes(); len(w) != 1 || !strings.Contains(w[0].Body, `"value":"one\n\ntwo\n\nReason: r"`) || strings.Count(w[0].Body, "append_comment") != 1 {
		t.Errorf("writes = %+v", w)
	}

	// Parameters outside triage are refused.
	if _, isErr, _ := call("falcon_alert", map[string]any{"action": "update", "ids": []string{"a:1"}, "params": map[string]any{"detection_suppress": "true"}, "reason": "r"}); !isErr {
		t.Error("detection_suppress accepted")
	}
}

func TestContainmentNote(t *testing.T) {
	f := &fakeWrites{replies: map[string]reply{
		"POST /devices/entities/devices/v2": {200, `{"resources":[{"device_id":"aid-1","hostname":"WS-0001"}]}`},
	}}
	call, logs := writeSession(t, []string{"containment"}, 0, f)
	if _, isErr, text := call("falcon_host", map[string]any{"action": "contain", "id": "aid-1", "confirm": "WS-0001", "reason": "active ransomware"}); isErr {
		t.Fatal(text)
	}
	w := f.writes()
	if len(w) != 1 || w[0].Path != "/devices/entities/devices-actions/v2" || query(t, w[0].Query).Get("action_name") != "contain" ||
		w[0].Body != `{"action_parameters":[{"name":"note","value":"active ransomware"}],"ids":["aid-1"]}` {
		t.Errorf("writes = %+v", w)
	}
	if !strings.Contains(logs.String(), `"reason":"active ransomware"`) {
		t.Errorf("log = %s", logs)
	}
}

func TestConfirmHostname(t *testing.T) {
	f := &fakeWrites{replies: map[string]reply{
		"POST /devices/entities/devices/v2": {200, `{"resources":[{"device_id":"aid-1","hostname":"WS-0001"}]}`},
	}}
	call, _ := writeSession(t, []string{"containment"}, 0, f)
	for _, args := range []map[string]any{
		{"action": "lift_containment", "id": "aid-1", "reason": "clean"},
		{"action": "lift_containment", "id": "aid-1", "confirm": "WS-0002", "reason": "clean"},
	} {
		_, isErr, text := call("falcon_host", args)
		if !isErr || !strings.Contains(text, "WS-0001") {
			t.Errorf("%v: %v %s", args, isErr, text)
		}
	}
	if _, isErr, _ := call("falcon_host", map[string]any{"action": "lift_containment", "ids": []string{"aid-1", "aid-2"}, "confirm": "WS-0001", "reason": "clean"}); !isErr {
		t.Error("two hosts accepted")
	}
	if w := f.writes(); len(w) != 0 {
		t.Errorf("sent %+v", w)
	}
	if _, isErr, text := call("falcon_host", map[string]any{"action": "lift_containment", "id": "aid-1", "confirm": "WS-0001", "reason": "clean"}); isErr {
		t.Fatal(text)
	}
	if w := f.writes(); len(w) != 1 || query(t, w[0].Query).Get("action_name") != "lift_containment" {
		t.Errorf("writes = %+v", w)
	}
}

func TestMaxBulkAndClamp(t *testing.T) {
	f := &fakeWrites{}
	call, _ := writeSession(t, []string{"host-tags", "triage"}, 3, f)
	ids := func(n int) []string {
		s := make([]string, n)
		for i := range s {
			s[i] = "x" + string(rune('a'+i))
		}
		return s
	}
	if _, isErr, text := call("falcon_host", map[string]any{"action": "add_tags", "ids": ids(4), "tags": []string{"t"}, "reason": "r"}); !isErr || !strings.Contains(text, "3") {
		t.Errorf("4 ids over --max-bulk 3: %v %s", isErr, text)
	}
	tags := make([]string, 51)
	for i := range tags {
		tags[i] = "t" + string(rune('a'+i))
	}
	if _, isErr, text := call("falcon_host", map[string]any{"action": "add_tags", "ids": ids(1), "tags": tags, "reason": "r"}); !isErr || !strings.Contains(text, "50") {
		t.Errorf("51 tags: %v %s", isErr, text)
	}
	if w := f.writes(); len(w) != 0 {
		t.Errorf("sent %+v", w)
	}
	if _, isErr, text := call("falcon_host", map[string]any{"action": "add_tags", "ids": ids(3), "tags": []string{"web", "FalconGroupingTags/db", "falcongroupingtags/x"}, "reason": "r"}); isErr {
		t.Fatal(text)
	}
	if w := f.writes(); len(w) != 1 || w[0].Body != `{"action":"add","device_ids":["xa","xb","xc"],"tags":["FalconGroupingTags/web","FalconGroupingTags/db","FalconGroupingTags/x"]}` {
		t.Errorf("writes = %+v", w)
	}

	// Falcon's own cap applies when it is below --max-bulk.
	big := &config.Config{MaxBulk: 5000}
	if got := (Deps{Config: big}).bulkCap(Action{MaxIDs: 1000}); got != 1000 {
		t.Errorf("cap = %d", got)
	}
}

func TestFilterWriteResolvesCountsAndConfirms(t *testing.T) {
	f := &fakeWrites{replies: map[string]reply{
		"GET /alerts/queries/alerts/v2": {200, `{"meta":{"pagination":{"total":2}},"resources":["a:1","a:2"]}`},
	}}
	call, _ := writeSession(t, []string{"triage"}, 3, f)
	args := map[string]any{"action": "update", "filter": "status:'new'", "params": map[string]any{"update_status": "in_progress"}, "reason": "r"}

	_, isErr, text := call("falcon_alert", args)
	if !isErr || !strings.Contains(text, "confirm") || !strings.Contains(text, "2") {
		t.Errorf("no confirm: %v %s", isErr, text)
	}
	args["confirm"] = "3"
	if _, isErr, _ := call("falcon_alert", args); !isErr {
		t.Error("wrong count accepted")
	}
	if w := f.writes(); len(w) != 0 {
		t.Fatalf("sent %+v", w)
	}
	if q := query(t, f.seen[0].Query); q.Get("filter") != "status:'new'" {
		t.Errorf("resolve query = %s", f.seen[0].Query)
	}
	args["confirm"] = "2"
	if _, isErr, text := call("falcon_alert", args); isErr {
		t.Fatal(text)
	}
	if w := f.writes(); len(w) != 1 || !strings.Contains(w[0].Body, `"composite_ids":["a:1","a:2"]`) {
		t.Errorf("writes = %+v", w)
	}

	// Over --max-bulk: refused whatever confirm says.
	f.replies["GET /alerts/queries/alerts/v2"] = reply{200, `{"meta":{"pagination":{"total":4}},"resources":["a:1","a:2","a:3","a:4"]}`}
	args["confirm"] = "4"
	if _, isErr, text := call("falcon_alert", args); !isErr || !strings.Contains(text, "4") {
		t.Errorf("over cap: %v %s", isErr, text)
	}
	if _, isErr, _ := call("falcon_alert", map[string]any{"action": "update", "filter": "x", "ids": []string{"a:1"}, "params": map[string]any{"update_status": "closed"}, "reason": "r"}); !isErr {
		t.Error("ids and filter together accepted")
	}
}

func TestWritesAreNotRetried(t *testing.T) {
	for _, status := range []int{http.StatusTooManyRequests, http.StatusBadGateway} {
		f := &fakeWrites{replies: map[string]reply{
			"PATCH /devices/entities/devices/tags/v1": {status, `{"errors":[{"code":1,"message":"busy"}]}`},
		}}
		call, logs := writeSession(t, []string{"host-tags"}, 0, f)
		if _, isErr, _ := call("falcon_host", map[string]any{"action": "remove_tags", "ids": []string{"aid-1"}, "tags": []string{"t"}, "reason": "r"}); !isErr {
			t.Errorf("%d: no error", status)
		}
		if w := f.writes(); len(w) != 1 {
			t.Errorf("%d: %d attempts", status, len(w))
		}
		if !strings.Contains(logs.String(), `"msg":"falcon write failed"`) {
			t.Errorf("%d: log = %s", status, logs)
		}
	}
}

func TestCaseWrites(t *testing.T) {
	f := &fakeWrites{}
	call, _ := writeSession(t, []string{"triage"}, 0, f)
	for _, c := range []struct {
		args               map[string]any
		method, path, body string
	}{
		{map[string]any{"action": "create", "body": map[string]any{"name": "n", "severity": 3}}, "PUT", "/cases/entities/cases/v2", `{"name":"n","severity":3}`},
		{map[string]any{"action": "update", "id": "c1", "body": map[string]any{"status": "closed"}}, "PATCH", "/cases/entities/cases/v2", `{"fields":{"status":"closed"},"id":"c1"}`},
		{map[string]any{"action": "add_alert_evidence", "id": "c1", "ids": []string{"a:1"}}, "POST", "/cases/entities/alert-evidence/v1", `{"alerts":[{"id":"a:1"}],"id":"c1"}`},
		{map[string]any{"action": "add_event_evidence", "id": "c1", "ids": []string{"e1"}}, "POST", "/cases/entities/event-evidence/v1", `{"events":[{"id":"e1"}],"id":"c1"}`},
		{map[string]any{"action": "add_tags", "id": "c1", "tags": []string{"t"}}, "POST", "/cases/entities/case-tags/v1", `{"id":"c1","tags":["t"]}`},
		{map[string]any{"action": "remove_tags", "id": "c1", "tags": []string{"t"}}, "DELETE", "/cases/entities/case-tags/v1", ``},
	} {
		f.reset()
		c.args["reason"] = "r"
		if _, isErr, text := call("falcon_case", c.args); isErr {
			t.Errorf("%v: %s", c.args, text)
			continue
		}
		if w := f.writes(); len(w) != 1 || w[0].Method != c.method || w[0].Path != c.path || w[0].Body != c.body {
			t.Errorf("%v: writes = %+v", c.args, w)
		}
	}
	if q := query(t, f.seen[0].Query); q.Get("id") != "c1" || q.Get("tag") != "t" {
		t.Errorf("remove_tags query = %s", f.seen[0].Query)
	}
	f.reset()
	if _, isErr, _ := call("falcon_case", map[string]any{"action": "add_alert_evidence", "id": "c1", "filter": "x", "reason": "r"}); !isErr || len(f.requests()) != 0 {
		t.Errorf("filter on an ids-only write: %v, sent %+v", isErr, f.requests())
	}
}
