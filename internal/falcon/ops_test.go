package falcon

import (
	"regexp"
	"testing"
)

var scopeShape = regexp.MustCompile(`^[A-Za-z0-9 ()-]+:(read|write)$`)

func TestOpTable(t *testing.T) {
	if len(ops) < 200 {
		t.Fatalf("only %d ops", len(ops))
	}
	for id, op := range ops {
		switch op.Method {
		case "GET", "POST", "PUT", "PATCH", "DELETE":
		default:
			t.Errorf("%s: method %q", id, op.Method)
		}
		if len(op.Path) < 2 || op.Path[0] != '/' {
			t.Errorf("%s: path %q", id, op.Path)
		}
		if !scopeShape.MatchString(op.Scope) {
			t.Errorf("%s: scope %q", id, op.Scope)
		}
		if op.Method == "GET" && op.Write {
			t.Errorf("%s: a GET marked as a write", id)
		}
	}
	// The write bit follows what an op does, not its method.
	for id, write := range map[string]bool{
		"PostDeviceDetailsV2": false, "post_graphql": false, "StartSearchV1": false,
		"PerformActionV2": true, "RTR_InitSession": true, "UpdateDeviceTags": true,
	} {
		if op, ok := Lookup(id); !ok || op.Write != write {
			t.Errorf("%s: %+v, want write=%t", id, op, write)
		}
	}
	for _, id := range []string{"queryAgentsV1", "QueryAgentsV2", "InvokePublishedAgentExternalV1"} { // /aidr and /agentic-studio
		if _, ok := Lookup(id); !ok {
			t.Errorf("%s missing", id)
		}
	}
}
