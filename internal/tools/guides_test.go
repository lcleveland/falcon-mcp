package tools

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/falcon-mcp/guides"
	"github.com/lcleveland/falcon-mcp/internal/config"
	"github.com/lcleveland/falcon-mcp/internal/falcon"
)

func resources(t *testing.T, cs *mcp.ClientSession) []string {
	t.Helper()
	res, err := cs.ListResources(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var uris []string
	for _, r := range res.Resources {
		uris = append(uris, r.URI)
	}
	return uris
}

func TestGuideResourcesFollowVisibility(t *testing.T) {
	probes := &falcon.Probes{Results: map[string]falcon.ProbeResult{"Alerts:read": {State: falcon.ProbeMissing}}}
	cs := sessionWith(t, &config.Config{Groups: []string{"respond", "hosts"}}, probes, http.StatusCreated, (&fixtures{}).ServeHTTP)
	got := resources(t, cs)
	for _, want := range []string{"falcon://hosts/search/fql-guide", "falcon://cases/search/fql-guide", "falcon://rtr/workflows/investigation-guide"} {
		if !slices.Contains(got, want) {
			t.Errorf("%s not listed", want)
		}
	}
	// Alerts refused by the probe; ngsiem's group is off.
	for _, hidden := range []string{"falcon://detections/search/fql-guide", "falcon://ngsiem/search/cql-guide", "falcon://guardian/entities/schema-guide"} {
		if slices.Contains(got, hidden) {
			t.Errorf("%s listed", hidden)
		}
	}

	// action=guide serves the resource's text, by name or URI.
	rr, err := cs.ReadResource(context.Background(), &mcp.ReadResourceParams{URI: "falcon://hosts/search/fql-guide"})
	if err != nil || len(rr.Contents) != 1 || !strings.Contains(rr.Contents[0].Text, "FQL") {
		t.Fatalf("read: %v %+v", err, rr)
	}
	for _, name := range []string{"hosts/search/fql-guide", "falcon://hosts/search/fql-guide"} {
		_, isErr, text := callTool(t, cs, "falcon_status", map[string]any{"action": "guide", "name": name})
		if isErr || text != rr.Contents[0].Text {
			t.Errorf("guide %s: isErr %t, %d bytes vs %d", name, isErr, len(text), len(rr.Contents[0].Text))
		}
	}
	if _, isErr, text := callTool(t, cs, "falcon_status", map[string]any{"action": "guide", "name": "detections/search/fql-guide"}); !isErr || !strings.Contains(text, "hosts/search/fql-guide") {
		t.Errorf("hidden guide served: %s", text)
	}
	// The check lists the same guides.
	out, _, _ := callTool(t, cs, "falcon_status", nil)
	if g, _ := out["guides"].([]any); len(g) != len(got) || !slices.Contains(g, any("hosts/search/fql-guide")) {
		t.Errorf("status guides = %v, resources = %v", g, got)
	}
}

// Actions whose Falcon filter has no upstream guide; their help gives examples.
var noGuide = []string{
	"falcon_case list_templates", "falcon_zta search", "falcon_cloud list_insight_definitions",
	"falcon_cloud search_suppression_rules", "falcon_cloud search_groups",
}

func TestEveryFilterNamesAGuide(t *testing.T) {
	cs := sessionWith(t, &config.Config{}, nil, http.StatusCreated, (&fixtures{}).ServeHTTP)
	tl := listTools(t, cs)
	for _, tool := range Tools() {
		for _, u := range tool.Guides {
			if _, ok := guides.Text(u); !ok {
				t.Errorf("%s: guide %s does not exist", tool.Name, u)
			}
		}
		b, _ := json.Marshal(tl[tool.Name].InputSchema)
		var s struct {
			Properties map[string]struct{ Description string } `json:"properties"`
		}
		json.Unmarshal(b, &s)
		for _, a := range tool.Actions {
			if a.Guide != "" {
				if _, ok := guides.Text(a.Guide); !ok {
					t.Errorf("%s %s: guide %s does not exist", tool.Name, a.Name, a.Guide)
				}
			}
			if !slices.Contains(a.inputs(tool.TypeParam), "filter") {
				continue
			}
			switch {
			case a.Guide == "" && !slices.Contains(noGuide, tool.Name+" "+a.Name):
				t.Errorf("%s %s takes a filter but names no guide", tool.Name, a.Name)
			case a.Guide != "" && !strings.Contains(s.Properties["filter"].Description, a.Guide):
				t.Errorf("%s filter description %q does not name %s", tool.Name, s.Properties["filter"].Description, a.Guide)
			}
		}
	}
}
