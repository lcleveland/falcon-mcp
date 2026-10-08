package tools

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lcleveland/falcon-mcp/internal/config"
	"github.com/lcleveland/falcon-mcp/internal/falcon"
)

// Every table action reaches its op's route with the inputs it advertises.
func TestEveryActionCallsItsRoute(t *testing.T) {
	var mu sync.Mutex
	var seen []request
	all := &config.Config{Allow: map[string]bool{}}
	for _, c := range config.Capabilities {
		all.Allow[c] = true
	}
	cs := sessionWith(t, all, nil, http.StatusCreated, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		seen = append(seen, request{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery})
		mu.Unlock()
		io.WriteString(w, `{"meta":{"pagination":{"total":1}},"resources":[{"id":"x"}]}`)
	})
	for _, tl := range Tools() {
		for _, a := range tl.Actions {
			if a.Kind == Custom || a.Kind == Write {
				continue // tested on their own
			}
			args := map[string]any{"action": a.Name}
			if tl.TypeParam != "" {
				args[tl.TypeParam] = a.Type
			}
			switch {
			case a.Kind == Get || a.TakesIDs:
				args["ids"] = []string{"x"}
			case a.Param != "":
				args["id"] = "x"
			}
			if op, _ := falcon.Lookup(a.Op); op.Method == http.MethodPost && a.Kind == Aggregate {
				args["body"] = []any{}
			}
			mu.Lock()
			seen = nil
			mu.Unlock()
			if _, isErr, text := callTool(t, cs, tl.Name, args); isErr {
				t.Errorf("%s %s %s: %s", tl.Name, a.Name, a.Type, text)
				continue
			}
			op, _ := falcon.Lookup(a.Op)
			if len(seen) == 0 || seen[0].Method != op.Method || seen[0].Path != op.Path {
				t.Errorf("%s %s %s: requests %+v, want %s %s first", tl.Name, a.Name, a.Type, seen, op.Method, op.Path)
			}
			for k, v := range a.Set {
				if q := query(t, seen[0].Query); !slices.Equal(q[k], v) {
					t.Errorf("%s %s: %s = %v, want %v", tl.Name, a.Name, k, q[k], v)
				}
			}
		}
	}
}

func TestPerTypeDropping(t *testing.T) {
	probes := &falcon.Probes{Results: map[string]falcon.ProbeResult{
		"Device Control Policies:read":     {State: falcon.ProbeMissing},
		"Machine Learning Exclusions:read": {State: falcon.ProbeMissing},
	}}
	f := &fixtures{routes: map[string]string{"/policy/combined/prevention/v1": "host_groups_combined.json"}}
	call := fixtureSession(t, nil, probes, f)
	cs := sessionWith(t, &config.Config{}, probes, http.StatusCreated, f.ServeHTTP)
	tl := listTools(t, cs)

	enum := func(tool, prop string) []string {
		b, _ := json.Marshal(tl[tool].InputSchema)
		var s struct {
			Properties map[string]struct{ Enum []string } `json:"properties"`
		}
		json.Unmarshal(b, &s)
		return s.Properties[prop].Enum
	}
	if e := enum("falcon_policy", "policy_type"); slices.Contains(e, "device_control") || !slices.Contains(e, "prevention") {
		t.Errorf("policy_type enum = %v", e)
	}
	// Certificate exclusions live under the ML scope too.
	if e := enum("falcon_exclusion", "exclusion_type"); !slices.Equal(e, []string{"ioa", "sensor_visibility"}) {
		t.Errorf("exclusion_type enum = %v", e)
	}
	if e := enum("falcon_exclusion", "action"); slices.Contains(e, "get_certificate_details") {
		t.Errorf("exclusion actions = %v", e)
	}
	if strings.Contains(tl["falcon_policy"].Description, "device_control") {
		t.Errorf("dropped type still described: %s", tl["falcon_policy"].Description)
	}

	if _, isErr, text := call("falcon_policy", map[string]any{"action": "search", "policy_type": "device_control"}); !isErr || !strings.Contains(text, "prevention") {
		t.Errorf("dropped type ran: %s", text)
	}
	if _, isErr, text := call("falcon_policy", map[string]any{"action": "search"}); !isErr || !strings.Contains(text, "needs policy_type") {
		t.Errorf("no type: %s", text)
	}
	f.reset()
	if _, isErr, text := call("falcon_policy", map[string]any{"action": "search", "policy_type": "prevention"}); isErr || f.requests()[0].Path != "/policy/combined/prevention/v1" {
		t.Errorf("prevention: %s %v", text, f.requests())
	}
}

func TestParamsAndFiles(t *testing.T) {
	var got []request
	cs := sessionWith(t, &config.Config{}, nil, http.StatusCreated, func(w http.ResponseWriter, r *http.Request) {
		got = append(got, request{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery})
		w.Header().Set("Content-Type", "application/octet-stream")
		io.WriteString(w, "id,tactic_id\n1,TA0001\n")
	})
	out, isErr, text := callTool(t, cs, "falcon_intel", map[string]any{"action": "get_mitre_report", "params": map[string]any{"actor_id": "1", "format": "csv"}})
	if isErr || out["results"] != "id,tactic_id\n1,TA0001\n" {
		t.Fatalf("csv: %s %v", text, out)
	}
	if q := query(t, got[0].Query); q.Get("actor_id") != "1" || q.Get("format") != "csv" {
		t.Errorf("query = %s", got[0].Query)
	}
	if _, isErr, text := callTool(t, cs, "falcon_intel", map[string]any{"action": "get_mitre_report", "params": map[string]any{"bogus": "1"}}); !isErr || !strings.Contains(text, "actor_id") {
		t.Errorf("unknown param: %s", text)
	}
	if _, isErr, text := callTool(t, cs, "falcon_intel", map[string]any{"action": "get_mitre_report", "filter": "x:1"}); !isErr || !strings.Contains(text, "no filter") {
		t.Errorf("filter on a no-filter action: %s", text)
	}
	if _, isErr, text := callTool(t, cs, "falcon_report", map[string]any{"action": "download_execution", "ids": []string{"a", "b"}}); !isErr || !strings.Contains(text, "exactly one id") {
		t.Errorf("two ids to a one-id op: %s", text)
	}
	got = nil
	callTool(t, cs, "falcon_guardian", map[string]any{"action": "get_process_tree", "ids": []string{"s-1"}})
	if q := query(t, got[0].Query); q.Get("id") != "s-1" || q.Has("ids") {
		t.Errorf("one:id query = %s", got[0].Query)
	}
}

func TestGraphQLRefusesWrites(t *testing.T) {
	for doc, want := range map[string]string{
		`{entities(first: 1) {nodes {primaryDisplayName}}}`:                         "",
		`query Q($t: [EntityType!]) {entities(types: $t) {pageInfo {hasNextPage}}}`: "",
		`# mutation in a comment
		query { a(note: "mutation { x }") }`: "",
		`query { a(note: """ } mutation { """) }`:                                               "",
		`mutation { addEntitiesToWatchList(input: {}) {updatedEntities {primaryDisplayName}} }`: "mutation",
		`query A { a } mutation B { b }`:                                                        "mutation",
		`subscription { s }`:                                                                    "subscription",
		`query { a(note: "unterminated) }`:                                                      "mutation",
		`} mutation { b } {`:                                                                    "mutation",
	} {
		if got := graphqlWrite(doc); got != want {
			t.Errorf("graphqlWrite(%q) = %q, want %q", doc, got, want)
		}
	}

	var bodies []string
	cs := sessionWith(t, &config.Config{}, nil, http.StatusCreated, func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		bodies = append(bodies, string(b))
		io.WriteString(w, `{"data":{"entities":{"nodes":[]}},"errors":[{"message":"partial"}]}`)
	})
	if _, isErr, text := callTool(t, cs, "falcon_identity", map[string]any{"action": "investigate_entity", "query": "mutation { x }"}); !isErr || !strings.Contains(text, "refused") || len(bodies) > 0 {
		t.Errorf("mutation: %s, sent %v", text, bodies)
	}
	out, isErr, text := callTool(t, cs, "falcon_identity", map[string]any{"action": "investigate_entity", "query": "{entities {nodes {riskScore}}}", "variables": map[string]any{"n": 1}})
	if isErr || out["results"] == nil || out["errors"] == nil || !strings.Contains(bodies[0], `"variables":{"n":1}`) {
		t.Errorf("query: %s %v %v", text, out, bodies)
	}
}

// fakeSIEM is an NGSIEM job API whose job finishes when done is set.
type fakeSIEM struct {
	mu      sync.Mutex
	done    bool
	polls   int
	stopped []string
	repos   []string
}

func (f *fakeSIEM) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	rest, _ := strings.CutPrefix(r.URL.Path, "/humio/api/v1/repositories/")
	repo, id, _ := strings.Cut(rest, "/queryjobs")
	id = strings.TrimPrefix(id, "/")
	switch r.Method {
	case http.MethodPost:
		f.repos = append(f.repos, repo)
		io.WriteString(w, `{"id":"job-1","hashedQueryOnView":"h"}`)
	case http.MethodGet:
		f.polls++
		if f.done {
			io.WriteString(w, `{"done":true,"cancelled":false,"events":[{"ComputerName":"ws-1","@timestamp":1759312800000}],"metaData":{"eventCount":1,"filterQuery":{"queryString":"head(1)"}}}`)
		} else {
			io.WriteString(w, `{"done":false,"events":[],"metaData":{"eventCount":0,"workDone":1,"totalWork":4}}`)
		}
	case http.MethodDelete:
		f.stopped = append(f.stopped, id)
	}
}

func (f *fakeSIEM) set(done bool) { f.mu.Lock(); f.done = done; f.mu.Unlock() }
func (f *fakeSIEM) stops() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.stopped)
}

func fastPolling(t *testing.T) {
	old := [3]time.Duration{pollFor, pollEvery, jobTTL}
	pollFor, pollEvery, jobTTL = 30*time.Millisecond, 5*time.Millisecond, 100*time.Millisecond
	t.Cleanup(func() { pollFor, pollEvery, jobTTL = old[0], old[1], old[2] })
}

func TestNGSIEMSearch(t *testing.T) {
	fastPolling(t)
	f := &fakeSIEM{}
	cs := sessionWith(t, &config.Config{}, nil, http.StatusCreated, f.ServeHTTP)
	search := func(args map[string]any) (map[string]any, bool, string) {
		args["action"] = "search"
		return callTool(t, cs, "falcon_ngsiem", args)
	}

	// Finishes within the call.
	f.set(true)
	out, isErr, text := search(map[string]any{"query": "head(1)"})
	if isErr || out["done"] != true || len(out["results"].([]any)) != 1 || out["next_cursor"] != nil || f.repos[0] != "search-all" {
		t.Fatalf("in-call: %s %v", text, out)
	}
	if ev := out["results"].([]any)[0].(map[string]any); ev["@timestamp"] != "2025-10-01T10:00:00Z" {
		t.Errorf("event time = %v", ev["@timestamp"])
	}

	// Still running: a cursor, then a resume that finishes.
	f.set(false)
	args := map[string]any{"query": "head(1)", "repository": "investigate_view", "start": "7d"}
	out, isErr, text = search(args)
	if isErr || out["done"] != false || out["next_cursor"] == nil {
		t.Fatalf("running: %s %v", text, out)
	}
	f.set(true)
	args["cursor"] = out["next_cursor"]
	if out, isErr, text = search(args); isErr || out["done"] != true || len(out["results"].([]any)) != 1 {
		t.Fatalf("resume: %s %v", text, out)
	}
	if len(f.stops()) != 0 {
		t.Errorf("finished jobs were stopped: %v", f.stops())
	}
	// A resumed job is gone from the table once done.
	if _, isErr, text := search(args); !isErr || !strings.Contains(text, "expired") {
		t.Errorf("second resume: %s", text)
	}
	// The cursor is bound to its query.
	args["query"] = "other"
	if _, isErr, text := search(args); !isErr || !strings.Contains(text, "does not belong") {
		t.Errorf("cursor on another query: %s", text)
	}

	// Nobody resumes: the job is stopped when its cursor expires.
	f.set(false)
	out, _, _ = search(map[string]any{"query": "head(1)"})
	deadline := time.Now().Add(2 * time.Second)
	for len(f.stops()) == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !slices.Equal(f.stops(), []string{"job-1"}) {
		t.Fatalf("stopped = %v", f.stops())
	}
	if _, isErr, text := search(map[string]any{"query": "head(1)", "cursor": out["next_cursor"]}); !isErr || !strings.Contains(text, "expired") {
		t.Errorf("expired cursor: %s", text)
	}
}

func TestNGSIEMRepositoryValidation(t *testing.T) {
	f := &fakeSIEM{done: true}
	cs := sessionWith(t, &config.Config{}, nil, http.StatusCreated, f.ServeHTTP)
	for _, repo := range []string{"a/b", `a\b`, "a%2fb", ".", "..", " "} {
		if _, isErr, text := callTool(t, cs, "falcon_ngsiem", map[string]any{"action": "search", "query": "x", "repository": repo}); !isErr || !strings.Contains(text, "plain repository") {
			t.Errorf("repository %q: %s", repo, text)
		}
	}
	if len(f.repos) != 0 {
		t.Errorf("a bad repository reached Falcon: %v", f.repos)
	}
	if _, isErr, text := callTool(t, cs, "falcon_ngsiem", map[string]any{"action": "search", "query": "x", "repository": "a..b"}); isErr {
		t.Errorf("a..b is a plain name: %s", text)
	}
}

func TestNGSIEMShutdownStopsJobs(t *testing.T) {
	f := &fakeSIEM{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/oauth2/token" {
			w.WriteHeader(http.StatusCreated)
			io.WriteString(w, `{"access_token":"tok","expires_in":1799}`)
			return
		}
		f.ServeHTTP(w, r)
	}))
	defer srv.Close()
	js := newJobs(falcon.New("eu-1", srv.URL, "id", "secret", srv.Client(), nil), slog.New(slog.DiscardHandler))
	js.park(&job{repo: "search-all", id: "job-a", born: time.Now()})
	js.park(&job{repo: "search-all", id: "job-b", born: time.Now()})
	js.Close()
	if s := f.stops(); len(s) != 2 {
		t.Errorf("stopped = %v", s)
	}
}

func TestReviewFixes(t *testing.T) {
	var got []request
	body := `{"meta":{"pagination":{"offset":0,"limit":2,"total":2}},"resources":[{"Id":"a"},{"Id":"b"}]}`
	cs := sessionWith(t, &config.Config{}, nil, http.StatusCreated, func(w http.ResponseWriter, r *http.Request) {
		got = append(got, request{Method: r.Method, Path: r.URL.Path, Query: r.URL.RawQuery})
		io.WriteString(w, body)
	})
	// Big numbers go out as integers, not 1e+12.
	callTool(t, cs, "falcon_guardian", map[string]any{"action": "get_process_tree", "ids": []string{"s"}, "params": map[string]any{"depth": 1759312800000.0}})
	if q := query(t, got[0].Query); q.Get("depth") != "1759312800000" {
		t.Errorf("depth = %q", q.Get("depth"))
	}
	// AIDR reports offset+len as total: a full page still pages on.
	out, _, _ := callTool(t, cs, "falcon_guardian", map[string]any{"action": "search_agents", "limit": 2})
	if out["next_cursor"] == nil {
		t.Errorf("AIDR full page has no cursor: %v", out)
	}
	// Other APIs trust total.
	out, _, _ = callTool(t, cs, "falcon_host_group", map[string]any{"action": "search", "limit": 2})
	if out["next_cursor"] != nil {
		t.Errorf("total reached but cursor given: %v", out)
	}
	if _, isErr, text := callTool(t, cs, "falcon_policy", map[string]any{"action": "search", "exclusion_type": "ioa"}); !isErr || !strings.Contains(text, "exclusion_type") {
		t.Errorf("wrong type field: %s", text)
	}
	if _, isErr, text := callTool(t, cs, "falcon_identity", map[string]any{"action": "investigate_entity", "query": "{a}", "cursor": "x"}); !isErr || !strings.Contains(text, "cursor") {
		t.Errorf("cursor on identity: %s", text)
	}
}
