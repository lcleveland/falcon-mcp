package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"testing"

	"github.com/lcleveland/falcon-mcp/internal/config"
	"github.com/lcleveland/falcon-mcp/internal/falcon"
)

func fixtureSession(t *testing.T, cfg *config.Config, probes *falcon.Probes, f *fixtures) func(string, map[string]any) (map[string]any, bool, string) {
	t.Helper()
	if cfg == nil {
		cfg = &config.Config{}
	}
	cs := sessionWith(t, cfg, probes, http.StatusCreated, f.ServeHTTP)
	return func(name string, args map[string]any) (map[string]any, bool, string) {
		t.Helper()
		return callTool(t, cs, name, args)
	}
}

func query(t *testing.T, raw string) url.Values {
	t.Helper()
	q, err := url.ParseQuery(raw)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func TestSearchQueryThenGetWithOffsetPaging(t *testing.T) {
	f := &fixtures{routes: map[string]string{
		"/devices/queries/devices/v1":  "hosts_query.json",
		"/devices/entities/devices/v2": "hosts_entities.json",
	}}
	call := fixtureSession(t, nil, nil, f)

	out, isErr, text := call("falcon_host", map[string]any{"action": "search", "filter": "platform_name:'Windows'", "limit": 2})
	if isErr {
		t.Fatal(text)
	}
	reqs := f.requests()
	if len(reqs) != 2 || reqs[0].Method != "GET" || reqs[1].Method != "POST" || reqs[1].Body != `{"ids":["aid-0001","aid-0002"]}` {
		t.Fatalf("requests = %+v", reqs)
	}
	if q := query(t, reqs[0].Query); q.Get("filter") != "platform_name:'Windows'" || q.Get("limit") != "2" || q.Has("offset") {
		t.Errorf("first page query = %s", reqs[0].Query)
	}
	res := out["results"].([]any)
	if len(res) != 2 || out["total"] != 5.0 || out["next_cursor"] == nil {
		t.Fatalf("out = %v", out)
	}
	// Brief projection, and times normalised to UTC.
	h := res[0].(map[string]any)
	if _, ok := h["bios_version"]; ok || h["hostname"] != "ws-alpha" || h["last_seen"] != "2026-10-01T10:00:00Z" {
		t.Errorf("brief host = %v", h)
	}

	f.reset()
	call("falcon_host", map[string]any{"action": "search", "filter": "platform_name:'Windows'", "limit": 2, "cursor": out["next_cursor"]})
	if q := query(t, f.requests()[0].Query); q.Get("offset") != "2" {
		t.Errorf("second page query = %s", f.requests()[0].Query)
	}
}

func TestSearchCombined(t *testing.T) {
	f := &fixtures{routes: map[string]string{"/devices/combined/host-groups/v1": "host_groups_combined.json"}}
	call := fixtureSession(t, nil, nil, f)
	out, isErr, text := call("falcon_host_group", map[string]any{"action": "search"})
	if isErr || len(f.requests()) != 1 {
		t.Fatal(text, f.requests())
	}
	g := out["results"].([]any)[0].(map[string]any)
	if g["name"] != "Lab machines" || g["created_by"] != nil {
		t.Errorf("group = %v", g)
	}
	if _, ok := out["next_cursor"]; ok {
		t.Errorf("one result of a total of one has no next page: %v", out)
	}

	// An action's id input fills its query parameter.
	f.routes["/devices/combined/host-group-members/v1"] = "hosts_entities.json"
	f.reset()
	if _, isErr, text := call("falcon_host_group", map[string]any{"action": "search_members", "id": "grp-1"}); isErr || query(t, f.requests()[0].Query).Get("id") != "grp-1" {
		t.Errorf("members: %s %v", text, f.requests())
	}
	if _, isErr, text := call("falcon_host_group", map[string]any{"action": "search_members"}); !isErr || !strings.Contains(text, "needs id") {
		t.Errorf("members without id: %s", text)
	}
}

func TestSearchAfterPagingAndFixedFilter(t *testing.T) {
	f := &fixtures{routes: map[string]string{"/discover/combined/hosts/v1": "assets_combined.json"}}
	call := fixtureSession(t, nil, nil, f)
	out, _, text := call("falcon_discover", map[string]any{"action": "search_managed_assets", "filter": "platform_name:'Linux'"})
	if q := query(t, f.requests()[0].Query); q.Get("filter") != "entity_type:'managed'+platform_name:'Linux'" {
		t.Errorf("filter = %q", q.Get("filter"))
	}
	if out["next_cursor"] == nil {
		t.Fatal(text, out)
	}
	f.reset()
	call("falcon_discover", map[string]any{"action": "search_managed_assets", "filter": "platform_name:'Linux'", "cursor": out["next_cursor"]})
	if q := query(t, f.requests()[0].Query); q.Get("after") != "after-token-2" || q.Has("offset") {
		t.Errorf("after query = %s", f.requests()[0].Query)
	}
}

func TestFieldsProjection(t *testing.T) {
	f := &fixtures{routes: map[string]string{
		"/devices/queries/devices/v1":  "hosts_query.json",
		"/devices/entities/devices/v2": "hosts_entities.json",
	}}
	call := fixtureSession(t, nil, nil, f)
	out, _, _ := call("falcon_host", map[string]any{"action": "search", "fields": []string{"hostname", "device_policies.prevention.applied"}})
	h := out["results"].([]any)[1].(map[string]any)
	want := `{"device_policies":{"prevention":{"applied":false}},"hostname":"srv-beta"}`
	if b, _ := json.Marshal(h); string(b) != want {
		t.Errorf("projected = %s", b)
	}

	// get returns full entities unless fields is given.
	out, _, _ = call("falcon_host", map[string]any{"action": "get", "ids": []string{"aid-0001"}})
	if h := out["results"].([]any)[0].(map[string]any); h["bios_version"] != "1.2.3" {
		t.Errorf("get = %v", h)
	}
	if r := f.requests(); r[len(r)-1].Body != `{"ids":["aid-0001"]}` {
		t.Errorf("get body = %s", r[len(r)-1].Body)
	}
}

func TestLimitsAndByteCap(t *testing.T) {
	var limits []string
	big := make([]string, 0, 200)
	for i := range 200 {
		big = append(big, fmt.Sprintf(`{"id":"grp-%d","name":"%s"}`, i, strings.Repeat("x", 1000)))
	}
	body := `{"meta":{"pagination":{"offset":0,"total":1000}},"resources":[` + strings.Join(big, ",") + `]}`
	cs := sessionWith(t, &config.Config{}, nil, http.StatusCreated, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			limits = append(limits, r.URL.Query().Get("limit"))
		}
		w.Write([]byte(body))
	})
	out, _, _ := callTool(t, cs, "falcon_host_group", map[string]any{"action": "search", "limit": 500})
	if limits[0] != "200" {
		t.Errorf("limit sent = %s, want the 200 cap", limits[0])
	}
	tr, _ := out["_truncation"].(map[string]any)
	res := out["results"].([]any)
	if tr == nil || tr["of"] != 200.0 || len(res) >= 200 || !strings.Contains(tr["note"].(string), "repeat with a lower limit or pass fields") {
		t.Fatalf("truncation = %v (%d results)", tr, len(res))
	}
	if b, _ := json.Marshal(res); len(b) > maxBytes {
		t.Errorf("results are %d bytes", len(b))
	}
	// The cursor still points past the whole page.
	pos, err := decodeCursor(queryKey("falcon_host_group", "search", "", "", "", "", []string(nil), map[string]any(nil)), out["next_cursor"].(string))
	if err != nil || pos != "200" {
		t.Errorf("cursor = %q, %v", pos, err)
	}
}

func TestFalconMaxLimitClamps(t *testing.T) {
	var limit string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			w.WriteHeader(http.StatusCreated)
			w.Write([]byte(`{"access_token":"tok","expires_in":1799}`))
			return
		}
		limit = r.URL.Query().Get("limit")
		w.Write([]byte(`{"resources":[]}`))
	}))
	defer srv.Close()
	d := Deps{Client: falcon.New("eu-1", srv.URL, "id", "secret", nil, nil), Config: &config.Config{}}
	a := Action{Name: "search", Kind: Search, Op: "queryCombinedHostGroups", MaxLimit: 100}
	if _, err := d.read(context.Background(), "t", a, Input{Limit: 150}); err != nil || limit != "100" {
		t.Errorf("limit = %s, %v", limit, err)
	}
}

func TestOversizedSingleItem(t *testing.T) {
	huge := `{"resources":[{"device_id":"aid-0001","hostname":"ws-alpha","blob":"` + strings.Repeat("x", maxBytes+10) + `"}]}`
	cs := sessionWith(t, &config.Config{}, nil, http.StatusCreated, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte(huge)) })
	out, _, _ := callTool(t, cs, "falcon_host", map[string]any{"action": "get", "ids": []string{"aid-0001"}})
	if b, _ := json.Marshal(out); len(b) > maxBytes || !strings.Contains(string(b), "blob") {
		t.Errorf("oversized get is %d bytes: %.300s", len(b), b)
	}
}

func TestHydrationKeepsQueryOrderAndErrors(t *testing.T) {
	cs := sessionWith(t, &config.Config{}, nil, http.StatusCreated, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Write([]byte(`{"meta":{"pagination":{"total":3}},"resources":["aid-0003","aid-0001","aid-0002"]}`))
			return
		}
		w.Write([]byte(`{"resources":[{"device_id":"aid-0001"},{"device_id":"aid-0002"},{"device_id":"aid-0003"}],"errors":[{"code":404,"message":"one id not found"}]}`))
	})
	out, _, _ := callTool(t, cs, "falcon_host", map[string]any{"action": "search", "sort": "last_seen.desc", "fields": []string{"device_id"}})
	var got []string
	for _, x := range out["results"].([]any) {
		got = append(got, x.(map[string]any)["device_id"].(string))
	}
	if strings.Join(got, ",") != "aid-0003,aid-0001,aid-0002" {
		t.Errorf("order = %v", got)
	}
	if e, _ := out["errors"].([]any); len(e) != 1 {
		t.Errorf("errors = %v", out["errors"])
	}
}

func TestAfterLastPageAndEpochTimes(t *testing.T) {
	cs := sessionWith(t, &config.Config{}, nil, http.StatusCreated, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"meta":{"pagination":{"after":""}},"resources":[{"id":"asset-1","last_seen_timestamp":1759449600,"created_on":1759449600000,"uptime":3600}]}`))
	})
	out, _, _ := callTool(t, cs, "falcon_discover", map[string]any{"action": "search_managed_assets", "fields": []string{"id", "last_seen_timestamp", "created_on", "uptime"}})
	if _, ok := out["next_cursor"]; ok {
		t.Errorf("an empty after token is the last page: %v", out)
	}
	a := out["results"].([]any)[0].(map[string]any)
	if a["last_seen_timestamp"] != "2025-10-03T00:00:00Z" || a["created_on"] != "2025-10-03T00:00:00Z" || a["uptime"] != 3600.0 {
		t.Errorf("times = %v", a)
	}
}

func TestEmptyFieldsMeansBrief(t *testing.T) {
	f := &fixtures{routes: map[string]string{"/devices/combined/host-groups/v1": "host_groups_combined.json"}}
	call := fixtureSession(t, nil, nil, f)
	out, _, _ := call("falcon_host_group", map[string]any{"action": "search", "fields": []string{}})
	if g := out["results"].([]any)[0].(map[string]any); g["name"] != "Lab machines" {
		t.Errorf("fields [] = %v", g)
	}
}

func TestCursorBoundToQuery(t *testing.T) {
	f := &fixtures{routes: map[string]string{
		"/devices/queries/devices/v1":  "hosts_query.json",
		"/devices/entities/devices/v2": "hosts_entities.json",
	}}
	call := fixtureSession(t, nil, nil, f)
	out, _, _ := call("falcon_host", map[string]any{"action": "search", "filter": "a:'1'"})
	cur := out["next_cursor"]
	for _, args := range []map[string]any{
		{"action": "search", "filter": "a:'2'", "cursor": cur},
		{"action": "search", "filter": "a:'1'", "sort": "hostname.asc", "cursor": cur},
		{"action": "search", "filter": "a:'1'", "fields": []string{"hostname"}, "cursor": cur},
		{"action": "search", "filter": "a:'1'", "cursor": "garbage"},
		{"action": "get", "ids": []string{"x"}, "cursor": cur},
	} {
		if _, isErr, text := call("falcon_host", args); !isErr || !strings.Contains(text, "cursor does not belong") {
			t.Errorf("%v: %s", args, text)
		}
	}
	if _, isErr, text := call("falcon_host", map[string]any{"action": "search", "filter": "a:'1'", "cursor": cur}); isErr {
		t.Errorf("same query rejected: %s", text)
	}
}

func TestAggregate(t *testing.T) {
	f := &fixtures{routes: map[string]string{"/billing-dashboards-usage/aggregates/weekly-average/v1": "usage_weekly.json"}}
	call := fixtureSession(t, nil, nil, f)
	out, isErr, text := call("falcon_sensor_usage", map[string]any{"action": "search_weekly", "filter": "period:'28'"})
	if isErr || len(out["results"].([]any)) != 1 || query(t, f.requests()[0].Query).Get("filter") != "period:'28'" {
		t.Errorf("weekly: %s %v", text, out)
	}
	// A POST aggregate needs its body.
	if _, isErr, text := call("falcon_alert", map[string]any{"action": "aggregate"}); !isErr || !strings.Contains(text, "needs body") {
		t.Errorf("aggregate without body: %s", text)
	}
}

func TestPartialScopeDropping(t *testing.T) {
	probes := &falcon.Probes{Results: map[string]falcon.ProbeResult{
		"Alerts:read":         {State: falcon.ProbeMissing},
		"Case Templates:read": {State: falcon.ProbeMissing},
		"Cases:read":          {State: falcon.ProbeOK},
		"Hosts:read":          {State: falcon.ProbeUnknown},
	}}
	cs := sessionWith(t, &config.Config{}, probes, http.StatusCreated, (&fixtures{}).ServeHTTP)
	tl := listTools(t, cs)
	if tl["falcon_alert"] != nil {
		t.Error("falcon_alert listed with Alerts:read refused")
	}
	if tl["falcon_host"] == nil {
		t.Error("an unknown probe must not hide falcon_host")
	}
	c := tl["falcon_case"]
	if c == nil {
		t.Fatal("falcon_case dropped entirely")
	}
	b, _ := json.Marshal(c.InputSchema)
	if strings.Contains(string(b), "list_templates") || strings.Contains(string(b), "aggregate_slas") || !strings.Contains(string(b), `"search"`) {
		t.Errorf("case schema = %s", b)
	}
	if strings.Contains(c.Description, "list_templates") {
		t.Error("dropped action still described")
	}
	if _, isErr, text := callTool(t, cs, "falcon_case", map[string]any{"action": "list_templates"}); !isErr || !strings.Contains(text, "list_templates") {
		t.Errorf("dropped action ran: %s", text)
	}
}

func TestToolGroups(t *testing.T) {
	cs := sessionWith(t, &config.Config{Groups: []string{"hosts"}}, nil, http.StatusCreated, (&fixtures{}).ServeHTTP)
	var names []string
	for n := range listTools(t, cs) {
		names = append(names, n)
	}
	slices.Sort(names)
	want := []string{"falcon_api", "falcon_discover", "falcon_host", "falcon_host_group", "falcon_sensor_usage", "falcon_status", "falcon_zta"}
	if !slices.Equal(names, want) {
		t.Errorf("tools = %v, want %v", names, want)
	}
}

// Every action resolves to an op in the table, a write exactly when the
// action is, with its hydration or resolve op a read under its family scope.
func TestToolTable(t *testing.T) {
	seen := map[string]bool{}
	for _, tl := range Tools() {
		if seen[tl.Name] || !slices.Contains(config.Groups, tl.Group) || tl.Group == "core" {
			t.Errorf("%s: duplicate or bad group %q", tl.Name, tl.Group)
		}
		seen[tl.Name] = true
		for _, a := range tl.Actions {
			op, ok := falcon.Lookup(a.Op)
			if !ok || op.Write != (a.Kind == Write) || (a.Kind == Write) != (a.Capability != "" && a.Send != nil) {
				t.Errorf("%s.%s: op %s missing, or its write bit, capability or Send disagrees with the kind", tl.Name, a.Name, a.Op)
			}
			if a.Capability != "" && !slices.Contains(config.Capabilities, a.Capability) {
				t.Errorf("%s.%s: unknown capability %q", tl.Name, a.Name, a.Capability)
			}
			if a.Resolve != "" {
				if r, ok := falcon.Lookup(a.Resolve); !ok || r.Write || r.Scope != falcon.FamilyRead(op.Scope) {
					t.Errorf("%s.%s: resolve op %s: %+v", tl.Name, a.Name, a.Resolve, r)
				}
			}
			if a.Hydrate != "" {
				if g, ok := falcon.Lookup(a.Hydrate); !ok || g.Write || g.Scope != op.Scope {
					t.Errorf("%s.%s: hydrate op %s: %+v", tl.Name, a.Name, a.Hydrate, g)
				}
			}
			if a.Kind == Search && a.Paging == After && a.Hydrate != "" {
				t.Errorf("%s.%s: after-paged hydration is untested", tl.Name, a.Name)
			}
		}
	}
}
