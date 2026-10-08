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
	"github.com/lcleveland/falcon-mcp/internal/falcon"
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

// Each write action is gated by exactly the capability the map gives it.
func TestCapabilityMap(t *testing.T) {
	want := map[string]string{
		"falcon_alert update": "triage", "falcon_case create": "triage", "falcon_case update": "triage",
		"falcon_case add_alert_evidence": "triage", "falcon_case add_event_evidence": "triage",
		"falcon_case add_tags": "triage", "falcon_case remove_tags": "triage",
		"falcon_host add_tags": "host-tags", "falcon_host remove_tags": "host-tags",
		"falcon_host contain": "containment", "falcon_host lift_containment": "containment",

		"falcon_ioc create": "detection-add", "falcon_ioc update": "detection-add",
		"falcon_custom_ioa create_rule_group": "detection-add", "falcon_custom_ioa create_rule": "detection-add",
		"falcon_custom_ioa enable_rule_group": "detection-add", "falcon_custom_ioa enable_rules": "detection-add",

		"falcon_ioc create_allow": "detection-remove", "falcon_ioc update_allow": "detection-remove", "falcon_ioc delete": "detection-remove",
		"falcon_custom_ioa disable_rule_group": "detection-remove", "falcon_custom_ioa disable_rules": "detection-remove",
		"falcon_custom_ioa delete_rule_groups": "detection-remove", "falcon_custom_ioa delete_rules": "detection-remove",
		"falcon_host suppress_detections": "detection-remove", "falcon_host unsuppress_detections": "detection-remove",
		"falcon_quarantine release": "detection-remove", "falcon_quarantine unrelease": "detection-remove",

		"falcon_host_group create": "fleet-config", "falcon_host_group update": "fleet-config", "falcon_host_group delete": "fleet-config",
		"falcon_host_group add_hosts": "fleet-config", "falcon_host_group remove_hosts": "fleet-config",
		"falcon_firewall create_rule_group": "fleet-config", "falcon_firewall update_rule_group": "fleet-config",
		"falcon_firewall delete_rule_groups": "fleet-config",

		"falcon_host hide_host": "destructive", "falcon_host unhide_host": "destructive", "falcon_quarantine delete": "destructive",

		"falcon_workflow execute": "workflows", "falcon_report launch": "workflows",
	}
	for _, typ := range []string{"ioa", "ml", "sensor_visibility", "certificate"} {
		for _, a := range []string{"create", "update", "delete"} {
			want["falcon_exclusion "+a+" "+typ] = "detection-remove"
		}
	}
	for _, typ := range []string{"prevention", "sensor_update", "firewall", "device_control", "response", "content_update"} {
		for _, a := range []string{"create", "update", "delete", "perform", "set_precedence"} {
			want["falcon_policy "+a+" "+typ] = "fleet-config"
		}
	}
	got := map[string]string{}
	for _, tl := range Tools() {
		for _, a := range tl.Actions {
			if a.Kind == Write {
				got[strings.TrimSpace(tl.Name+" "+a.Name+" "+a.Type)] = a.Capability
			}
		}
	}
	for k, c := range want {
		if got[k] != c {
			t.Errorf("%s: capability %q, want %q", k, got[k], c)
		}
	}
	for k, c := range got {
		if _, ok := want[k]; !ok {
			t.Errorf("%s: unexpected write (%s)", k, c)
		}
		if !slices.Contains(config.Capabilities, c) {
			t.Errorf("%s: capability %q has no flag", k, c)
		}
	}
}

// Never exposed, whatever the flags: no tool reaches these routes.
func TestNeverExposed(t *testing.T) {
	never := []string{"devices-actions-delete", "admin-command", "/real-time-response/entities/scripts", "/real-time-response/entities/put-files",
		"uninstall-token", "/user-management/", "/installation-tokens/", "/api-clients/"}
	cfg := &config.Config{Allow: map[string]bool{}, MaxBulk: 1000}
	for _, c := range config.Capabilities {
		cfg.Allow[c] = true
	}
	d := Deps{Config: cfg}
	for _, tl := range Tools() {
		for _, a := range d.actions(tl) {
			for _, id := range []string{a.Op, a.Hydrate, a.Resolve} {
				op, _ := falcon.Lookup(id)
				for _, n := range never {
					if strings.Contains(op.Path, n) {
						t.Errorf("%s %s reaches %s", tl.Name, a.Name, op.Path)
					}
				}
			}
		}
	}

	// Disabling uninstall protection is refused in any policy write.
	f := &fakeWrites{}
	call, _ := writeSession(t, []string{"fleet-config"}, 0, f)
	for _, args := range []map[string]any{
		{"action": "create", "policy_type": "sensor_update", "body": map[string]any{"name": "p", "settings": map[string]any{"uninstall_protection": "DISABLED"}}},
		{"action": "update", "policy_type": "sensor_update", "id": "p1", "body": map[string]any{"settings": map[string]any{"uninstall_protection": "MAINTENANCE_MODE"}}},
	} {
		args["reason"] = "r"
		if _, isErr, text := call("falcon_policy", args); !isErr || !strings.Contains(text, "uninstall") {
			t.Errorf("%v: %v %s", args, isErr, text)
		}
	}
	if w := f.writes(); len(w) != 0 {
		t.Errorf("sent %+v", w)
	}
	if _, isErr, text := call("falcon_policy", map[string]any{"action": "update", "policy_type": "sensor_update", "id": "p1", "reason": "r",
		"body": map[string]any{"settings": map[string]any{"uninstall_protection": "ENABLED"}}}); isErr {
		t.Error(text)
	}
}

// An IOC update cannot lower protection without detection-remove.
func TestIOCActionNeedsItsSide(t *testing.T) {
	f := &fakeWrites{}
	call, _ := writeSession(t, []string{"detection-add"}, 0, f)
	for _, args := range []map[string]any{
		{"action": "update", "ids": []string{"i1"}, "body": map[string]any{"action": "allow"}},
		{"action": "update", "ids": []string{"i1"}, "body": map[string]any{"action": "no_action", "severity": "low"}},
		{"action": "create", "body": map[string]any{"type": "domain", "value": "x.test", "action": "allow"}},
		{"action": "create", "body": []any{map[string]any{"type": "domain", "value": "x.test", "action": "prevent"}, map[string]any{"type": "domain", "value": "y.test"}}},
		{"action": "update_allow", "ids": []string{"i1"}, "body": map[string]any{"action": "allow"}},
	} {
		args["reason"] = "r"
		if _, isErr, text := call("falcon_ioc", args); !isErr {
			t.Errorf("%v accepted: %s", args, text)
		}
	}
	if w := f.writes(); len(w) != 0 {
		t.Fatalf("sent %+v", w)
	}

	call, _ = writeSession(t, []string{"detection-add", "detection-remove"}, 0, f)
	if _, isErr, _ := call("falcon_ioc", map[string]any{"action": "update_allow", "ids": []string{"i1"}, "body": map[string]any{"severity": "low"}, "reason": "r"}); !isErr {
		t.Error("update_allow without an allow action accepted")
	}
	if _, isErr, _ := call("falcon_ioc", map[string]any{"action": "create_allow", "body": map[string]any{"type": "domain", "value": "x.test", "action": "detect"}, "reason": "r"}); !isErr {
		t.Error("create_allow with detect accepted")
	}
	if _, isErr, text := call("falcon_ioc", map[string]any{"action": "update_allow", "ids": []string{"i1"}, "body": map[string]any{"action": "allow"}, "reason": "r"}); isErr {
		t.Fatal(text)
	}
	if w := f.writes(); len(w) != 1 || w[0].Body != `{"comment":"r","indicators":[{"action":"allow","id":"i1"}]}` {
		t.Errorf("writes = %+v", w)
	}
}

// Every write reaches its route, with the reason in Falcon's comment field
// where it has one.
func TestDetectionFleetWorkflowWrites(t *testing.T) {
	const group = `{"resources":[{"id":"g1","name":"G","description":"D","version":3,"enabled":false,"rules":[` +
		`{"instance_id":"1","name":"R","description":"RD","pattern_severity":"high","disposition_id":10,"field_values":[],"enabled":false}]}]}`
	f := &fakeWrites{replies: map[string]reply{
		"POST /devices/entities/devices/v2":     {200, `{"resources":[{"device_id":"aid-1","hostname":"WS-0001"}]}`},
		"GET /ioarules/entities/rule-groups/v1": {200, group},
		"GET /iocs/queries/indicators/v1":       {200, `{"meta":{"pagination":{"total":2}},"resources":["i1","i2"]}`},
	}}
	call, _ := writeSession(t, []string{"detection-add", "detection-remove", "fleet-config", "destructive", "workflows"}, 0, f)
	type c struct {
		tool         string
		args         map[string]any
		method, path string
		query        string // url-encoded, compared parsed; "" skips
		body         string
	}
	cases := []c{
		{"falcon_ioc", map[string]any{"action": "create", "body": map[string]any{"type": "sha256", "value": "abc", "action": "prevent"}, "params": map[string]any{"retrodetects": true}},
			"POST", "/iocs/entities/indicators/v1", "retrodetects=true", `{"comment":"r","indicators":[{"action":"prevent","type":"sha256","value":"abc"}]}`},
		{"falcon_ioc", map[string]any{"action": "create_allow", "body": []any{map[string]any{"type": "domain", "value": "ok.test", "action": "allow"}}},
			"POST", "/iocs/entities/indicators/v1", "", `{"comment":"r","indicators":[{"action":"allow","type":"domain","value":"ok.test"}]}`},
		{"falcon_ioc", map[string]any{"action": "update", "filter": "type:'domain'", "confirm": "2", "body": map[string]any{"severity": "low"}},
			"PATCH", "/iocs/entities/indicators/v1", "", `{"comment":"r","indicators":[{"id":"i1","severity":"low"},{"id":"i2","severity":"low"}]}`},
		{"falcon_ioc", map[string]any{"action": "delete", "ids": []string{"i1"}},
			"DELETE", "/iocs/entities/indicators/v1", "comment=r&ids=i1", ""},

		{"falcon_custom_ioa", map[string]any{"action": "create_rule_group", "body": map[string]any{"name": "g", "platform": "windows"}},
			"POST", "/ioarules/entities/rule-groups/v1", "", `{"comment":"r","name":"g","platform":"windows"}`},
		{"falcon_custom_ioa", map[string]any{"action": "create_rule", "body": map[string]any{"rulegroup_id": "g1", "name": "n"}},
			"POST", "/ioarules/entities/rules/v1", "", `{"comment":"r","name":"n","rulegroup_id":"g1"}`},
		{"falcon_custom_ioa", map[string]any{"action": "enable_rule_group", "id": "g1"},
			"PATCH", "/ioarules/entities/rule-groups/v1", "", `{"comment":"r","description":"D","enabled":true,"id":"g1","name":"G","rulegroup_version":3}`},
		{"falcon_custom_ioa", map[string]any{"action": "disable_rule_group", "id": "g1"},
			"PATCH", "/ioarules/entities/rule-groups/v1", "", `{"comment":"r","description":"D","enabled":false,"id":"g1","name":"G","rulegroup_version":3}`},
		{"falcon_custom_ioa", map[string]any{"action": "enable_rules", "id": "g1", "ids": []string{"1"}},
			"PATCH", "/ioarules/entities/rules/v2", "", `{"comment":"r","rule_updates":[{"description":"RD","disposition_id":10,"enabled":true,"field_values":[],"instance_id":"1","name":"R","pattern_severity":"high","rulegroup_version":3}],"rulegroup_id":"g1","rulegroup_version":3}`},
		{"falcon_custom_ioa", map[string]any{"action": "disable_rules", "id": "g1", "ids": []string{"1"}},
			"PATCH", "/ioarules/entities/rules/v2", "", `{"comment":"r","rule_updates":[{"description":"RD","disposition_id":10,"enabled":false,"field_values":[],"instance_id":"1","name":"R","pattern_severity":"high","rulegroup_version":3}],"rulegroup_id":"g1","rulegroup_version":3}`},
		{"falcon_custom_ioa", map[string]any{"action": "delete_rule_groups", "ids": []string{"g1"}},
			"DELETE", "/ioarules/entities/rule-groups/v1", "comment=r&ids=g1", ""},
		{"falcon_custom_ioa", map[string]any{"action": "delete_rules", "id": "g1", "ids": []string{"1"}},
			"DELETE", "/ioarules/entities/rules/v1", "comment=r&ids=1&rule_group_id=g1", ""},

		{"falcon_exclusion", map[string]any{"action": "create", "exclusion_type": "ml", "body": map[string]any{"value": "/x", "groups": []any{"all"}}},
			"POST", "/exclusions/entities/exclusions/v2", "", `{"exclusions":[{"comment":"r","groups":["all"],"value":"/x"}]}`},
		{"falcon_exclusion", map[string]any{"action": "update", "exclusion_type": "ml", "id": "e1", "body": map[string]any{"value": "/y"}},
			"PATCH", "/exclusions/entities/exclusions/v2", "", `{"comment":"r","id":"e1","value":"/y"}`},
		{"falcon_exclusion", map[string]any{"action": "create", "exclusion_type": "sensor_visibility", "body": map[string]any{"value": "/x"}},
			"POST", "/policy/entities/sv-exclusions/v1", "", `{"comment":"r","value":"/x"}`},
		{"falcon_exclusion", map[string]any{"action": "update", "exclusion_type": "ioa", "id": "e1", "body": map[string]any{"name": "n"}},
			"PATCH", "/exclusions/entities/ss-ioa-exclusions/v2", "", `{"exclusions":[{"comment":"r","id":"e1","name":"n"}]}`},
		{"falcon_exclusion", map[string]any{"action": "create", "exclusion_type": "certificate", "body": map[string]any{"name": "n"}},
			"POST", "/exclusions/entities/cert-based-exclusions/v1", "", `{"exclusions":[{"comment":"r","name":"n"}]}`},
		{"falcon_exclusion", map[string]any{"action": "delete", "exclusion_type": "sensor_visibility", "ids": []string{"e1", "e2"}},
			"DELETE", "/policy/entities/sv-exclusions/v1", "comment=r&ids=e1&ids=e2", ""},

		{"falcon_quarantine", map[string]any{"action": "release", "ids": []string{"q1"}},
			"PATCH", "/quarantine/entities/quarantined-files/v1", "", `{"action":"release","comment":"r","ids":["q1"]}`},
		{"falcon_quarantine", map[string]any{"action": "unrelease", "ids": []string{"q1"}},
			"PATCH", "/quarantine/entities/quarantined-files/v1", "", `{"action":"unrelease","comment":"r","ids":["q1"]}`},
		{"falcon_quarantine", map[string]any{"action": "delete", "ids": []string{"q1"}},
			"PATCH", "/quarantine/entities/quarantined-files/v1", "", `{"action":"delete","comment":"r","ids":["q1"]}`},

		{"falcon_host", map[string]any{"action": "hide_host", "id": "aid-1", "confirm": "WS-0001"},
			"POST", "/devices/entities/devices-actions/v2", "action_name=hide_host", `{"action_parameters":[{"name":"note","value":"r"}],"ids":["aid-1"]}`},
		{"falcon_host", map[string]any{"action": "unhide_host", "id": "aid-1", "confirm": "WS-0001"},
			"POST", "/devices/entities/devices-actions/v2", "action_name=unhide_host", `{"action_parameters":[{"name":"note","value":"r"}],"ids":["aid-1"]}`},
		{"falcon_host", map[string]any{"action": "suppress_detections", "id": "aid-1", "confirm": "WS-0001"},
			"POST", "/devices/entities/devices-actions/v2", "action_name=detection_suppress", `{"action_parameters":[{"name":"note","value":"r"}],"ids":["aid-1"]}`},
		{"falcon_host", map[string]any{"action": "unsuppress_detections", "id": "aid-1", "confirm": "WS-0001"},
			"POST", "/devices/entities/devices-actions/v2", "action_name=detection_unsuppress", `{"action_parameters":[{"name":"note","value":"r"}],"ids":["aid-1"]}`},

		{"falcon_host_group", map[string]any{"action": "create", "body": map[string]any{"name": "g", "group_type": "static"}},
			"POST", "/devices/entities/host-groups/v1", "", `{"resources":[{"group_type":"static","name":"g"}]}`},
		{"falcon_host_group", map[string]any{"action": "update", "id": "hg1", "body": map[string]any{"description": "d"}},
			"PATCH", "/devices/entities/host-groups/v1", "", `{"resources":[{"description":"d","id":"hg1"}]}`},
		{"falcon_host_group", map[string]any{"action": "delete", "ids": []string{"hg1"}},
			"DELETE", "/devices/entities/host-groups/v1", "ids=hg1", ""},
		{"falcon_host_group", map[string]any{"action": "add_hosts", "id": "hg1", "ids": []string{"a1", "a2"}},
			"POST", "/devices/entities/host-group-actions/v1", "action_name=add-hosts", `{"action_parameters":[{"name":"filter","value":"device_id:['a1','a2']"}],"ids":["hg1"]}`},
		{"falcon_host_group", map[string]any{"action": "remove_hosts", "id": "hg1", "ids": []string{"a1"}},
			"POST", "/devices/entities/host-group-actions/v1", "action_name=remove-hosts", `{"action_parameters":[{"name":"filter","value":"device_id:['a1']"}],"ids":["hg1"]}`},

		{"falcon_firewall", map[string]any{"action": "create_rule_group", "body": map[string]any{"name": "g"}, "params": map[string]any{"clone_id": "c1"}},
			"POST", "/fwmgr/entities/rule-groups/v1", "clone_id=c1&comment=r", `{"name":"g"}`},
		{"falcon_firewall", map[string]any{"action": "update_rule_group", "body": map[string]any{"id": "g1", "rulegroup_version": 2}},
			"PATCH", "/fwmgr/entities/rule-groups/v1", "comment=r", `{"id":"g1","rulegroup_version":2}`},
		{"falcon_firewall", map[string]any{"action": "delete_rule_groups", "ids": []string{"g1"}},
			"DELETE", "/fwmgr/entities/rule-groups/v1", "comment=r&ids=g1", ""},

		{"falcon_workflow", map[string]any{"action": "execute", "params": map[string]any{"definition_id": "d1"}, "body": map[string]any{"x": 1}},
			"POST", "/workflows/entities/execute/v1", "definition_id=d1", `{"x":1}`},
		{"falcon_report", map[string]any{"action": "launch", "id": "rp1"},
			"POST", "/reports/entities/scheduled-reports/execution/v1", "", `[{"id":"rp1"}]`},
	}
	for _, p := range []struct{ typ, base, wrap string }{
		{"prevention", "prevention", "resources"}, {"sensor_update", "sensor-update", "resources"}, {"firewall", "firewall", "resources"},
		{"device_control", "device-control", "policies"}, {"response", "response", "resources"}, {"content_update", "content-update", "resources"},
	} {
		cases = append(cases,
			c{"falcon_policy", map[string]any{"action": "create", "policy_type": p.typ, "body": map[string]any{"name": "p"}},
				"POST", "", "", `{"` + p.wrap + `":[{"name":"p"}]}`},
			c{"falcon_policy", map[string]any{"action": "update", "policy_type": p.typ, "id": "p1", "body": map[string]any{"description": "d"}},
				"PATCH", "", "", `{"` + p.wrap + `":[{"description":"d","id":"p1"}]}`},
			c{"falcon_policy", map[string]any{"action": "delete", "policy_type": p.typ, "ids": []string{"p1"}},
				"DELETE", "", "ids=p1", ""},
			c{"falcon_policy", map[string]any{"action": "perform", "policy_type": p.typ, "id": "p1", "params": map[string]any{"action_name": "add-host-group"},
				"body": []any{map[string]any{"name": "group_id", "value": "hg1"}}},
				"POST", "/policy/entities/" + p.base + "-actions/v1", "action_name=add-host-group", `{"action_parameters":[{"name":"group_id","value":"hg1"}],"ids":["p1"]}`},
			c{"falcon_policy", map[string]any{"action": "set_precedence", "policy_type": p.typ, "ids": []string{"p2", "p1"}, "params": map[string]any{"platform_name": "Windows"}},
				"POST", "/policy/entities/" + p.base + "-precedence/v1", "", `{"ids":["p2","p1"],"platform_name":"Windows"}`},
		)
	}
	for _, tc := range cases {
		f.reset()
		tc.args["reason"] = "r"
		if _, isErr, text := call(tc.tool, tc.args); isErr {
			t.Errorf("%s %v: %s", tc.tool, tc.args, text)
			continue
		}
		w := f.writes()
		if len(w) != 1 || w[0].Method != tc.method || (tc.path != "" && w[0].Path != tc.path) || w[0].Body != tc.body {
			t.Errorf("%s %v: writes = %+v", tc.tool, tc.args, w)
			continue
		}
		if tc.query != "" && query(t, w[0].Query).Encode() != query(t, tc.query).Encode() {
			t.Errorf("%s %v: query %s, want %s", tc.tool, tc.args, w[0].Query, tc.query)
		}
	}

	// Refusals send nothing.
	for _, tc := range []struct {
		tool string
		args map[string]any
	}{
		{"falcon_custom_ioa", map[string]any{"action": "enable_rules", "id": "g1", "ids": []string{"9"}}},
		{"falcon_host_group", map[string]any{"action": "add_hosts", "id": "hg1", "ids": []string{"a1'],hostname:*'"}}},
		{"falcon_workflow", map[string]any{"action": "execute"}},
		{"falcon_policy", map[string]any{"action": "perform", "policy_type": "prevention", "id": "p1"}},
		{"falcon_exclusion", map[string]any{"action": "update", "exclusion_type": "ml", "body": map[string]any{"value": "/y"}}},
	} {
		f.reset()
		tc.args["reason"] = "r"
		if _, isErr, text := call(tc.tool, tc.args); !isErr || len(f.writes()) != 0 {
			t.Errorf("%s %v: %v %s, sent %+v", tc.tool, tc.args, isErr, text, f.writes())
		}
	}
}
