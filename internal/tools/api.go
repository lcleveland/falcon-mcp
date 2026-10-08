package tools

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/falcon-mcp/internal/falcon"
)

// never marks a write falcon_api refuses whatever the capabilities.
const never = "never"

// apiWrites classifies the table's write ops that no typed action sends.
// Ops a typed action sends are classified by that action, and falcon_api
// sends the caller there so the action's rails apply. A regenerated table
// with a new write fails TestEveryWriteOpIsClassified until it lands here.
var apiWrites = map[string]string{
	// Batch respond and query-selected quarantine skip the one-host
	// confirm and the filter count.
	"BatchActiveResponderCmd": never,
	"UpdateQfByQuery":         never,

	"CreateSuppressionRule":    "detection-remove",
	"DeleteSuppressionRules":   "detection-add",
	"DismissAffectedEntityV3":  "detection-remove",
	"DismissSecurityCheckV3":   "detection-remove",
	"entities_rules_post_v1":   "detection-add",
	"entities_rules_patch_v1":  "detection-remove", // can disable a rule
	"entities_rules_delete_v1": "detection-remove",

	// An agent's blast radius is whatever it does, like a workflow's.
	"InvokeAgentVersionExternalV1":   "workflows",
	"InvokePublishedAgentExternalV1": "workflows",
}

// apiRoute is how falcon_api treats one op.
type apiRoute struct {
	tool       string // the typed tool that owns the op; falcon_api refuses it
	capability string // needed to call it here; never refuses it
}

// apiRoutes classifies every op falcon_api treats specially. Writes and
// custom actions (whose handlers carry checks, such as GraphQL's mutation
// refusal) stay with their typed tool; reads a capability gates keep it.
func apiRoutes() map[string]apiRoute {
	rs := map[string]apiRoute{}
	for id, c := range apiWrites {
		rs[id] = apiRoute{capability: c}
	}
	for _, t := range Tools() {
		for _, a := range t.Actions {
			switch {
			case a.Kind == Write || a.Kind == Custom:
				rs[a.Op] = apiRoute{tool: t.Name}
			case a.Capability != "" && rs[a.Op].tool == "":
				rs[a.Op] = apiRoute{capability: a.Capability}
			}
		}
	}
	return rs
}

type apiInput struct {
	Op         string            `json:"op,omitempty" jsonschema:"FalconPy operation ID, e.g. QueryDevicesByFilter; or give method and path instead"`
	PathParams map[string]string `json:"path_params,omitempty" jsonschema:"with op: values for the {name} parts of its route"`
	Method     string            `json:"method,omitempty" jsonschema:"HTTP method, with path"`
	Path       string            `json:"path,omitempty" jsonschema:"API path with values filled in, e.g. /devices/queries/devices/v1; no query string"`
	Query      map[string]any    `json:"query,omitempty" jsonschema:"query parameters, e.g. {\"filter\": \"platform_name:'Windows'\", \"limit\": 10}; a list repeats the parameter (ids)"`
	Body       any               `json:"body,omitempty" jsonschema:"JSON request body"`
	Reason     string            `json:"reason,omitempty" jsonschema:"required for writes: why, recorded in the audit log"`
}

func registerAPI(s *mcp.Server, d Deps) {
	rs := apiRoutes()
	on := d.Config.Enabled()
	desc := "Call any Falcon API operation without a dedicated tool, by FalconPy operation ID or by method and path. " +
		"Prefer the falcon_* tools when one fits: they page, trim and hydrate; this returns Falcon's reply as is (resources, meta, errors), capped in size.\n\n" +
		"Reads are allowed, except scopes the startup probe found missing. "
	if len(on) > 0 {
		desc += "Writes run only when their capability is enabled (" + strings.Join(on, ", ") + ") and require reason; " +
			"writes a typed tool owns must go through that tool, and writes this server cannot classify are refused. Writes are never retried."
	} else {
		desc += "Writes are disabled by the operator."
	}
	mcp.AddTool(s, &mcp.Tool{
		Name:        "falcon_api",
		Title:       "Falcon API (generic)",
		Description: desc,
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: len(on) == 0, DestructiveHint: new(len(on) > 0), OpenWorldHint: new(true)},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in apiInput) (*mcp.CallToolResult, map[string]any, error) {
		out, err := d.api(ctx, rs, in)
		return nil, out, err
	})
}

func (d Deps) api(ctx context.Context, rs map[string]apiRoute, in apiInput) (map[string]any, error) {
	id, op, p, err := apiOp(in)
	if err != nil {
		return nil, err
	}
	r := rs[id]
	switch {
	case r.tool != "":
		return nil, fmt.Errorf("%s is sent by %s, whose actions apply its rails (confirmation, bulk caps, allowlists); call that tool instead", id, r.tool)
	case r.capability == never:
		return nil, fmt.Errorf("%s is a write this server never exposes", id)
	case op.Write && r.capability == "":
		return nil, fmt.Errorf("%s is a write this server cannot classify, so it refuses it", id)
	case r.capability != "" && !d.Config.Allow[r.capability]:
		return nil, fmt.Errorf("%s needs the %s capability, which the operator has disabled", id, r.capability)
	case op.Scope != "" && !d.Probes.Allows(op.Scope):
		return nil, fmt.Errorf("the startup probe found this API client cannot use %s (missing scope or not licensed); restart the server after granting it", falcon.FamilyRead(op.Scope))
	}
	if !op.Write {
		raw, err := d.Client.DoOp(ctx, id, op, p)
		if err != nil {
			return nil, err
		}
		return apiResult(id, raw)
	}

	reason := strings.TrimSpace(in.Reason)
	if reason == "" {
		return nil, errors.New("reason is required for writes; say why, it is recorded in the audit log")
	}
	audit := []any{"tool", "falcon_api", "op", id, "capability", r.capability, "reason", reason}
	d.Log.Info("falcon write sending", audit...)
	raw, err := d.Client.DoOp(ctx, id, op, p)
	if err != nil {
		var ae *falcon.APIError
		if errors.As(err, &ae) {
			audit = append(audit, "status", ae.Status, "trace_id", ae.TraceID)
		}
		d.Log.Warn("falcon write failed", append(audit, "error", err.Error())...)
		return nil, err
	}
	out, err := apiResult(id, raw)
	meta, _ := out["meta"].(map[string]any)
	d.Log.Info("falcon write", append(audit, "trace_id", meta["trace_id"])...)
	return out, err
}

// apiPath is a concrete API path: no query, encoding, braces or dot segments.
var apiPath = regexp.MustCompile(`^(/[A-Za-z0-9_~:@,=+.-]+)+$`)

// apiOp finds the op the input names. A path in the table takes that op's
// write bit, scope and classification; an unlisted path is only a read.
func apiOp(in apiInput) (string, falcon.Op, falcon.Params, error) {
	p := falcon.Params{Query: url.Values{}, Body: in.Body}
	if err := queryValues("query", in.Query, p.Query); err != nil {
		return "", falcon.Op{}, p, err
	}
	switch {
	case in.Op != "" && in.Method == "" && in.Path == "":
		op, ok := falcon.Lookup(in.Op)
		if !ok {
			return "", op, p, fmt.Errorf("%q is not in the op table; give method and path instead (a write outside the table is refused)", in.Op)
		}
		p.Path = in.PathParams
		return in.Op, op, p, nil
	case in.Op != "" || in.Method == "" || in.Path == "" || in.PathParams != nil:
		return "", falcon.Op{}, p, errors.New("give op, or method and path, not both (path_params go with op)")
	}
	method := strings.ToUpper(in.Method)
	if !apiPath.MatchString(in.Path) || strings.Contains(in.Path+"/", "/./") || strings.Contains(in.Path+"/", "/../") {
		return "", falcon.Op{}, p, errors.New("path must be a Falcon API path like /devices/queries/devices/v1 (no host, query string, encoded characters or '..')")
	}
	for id, op := range falcon.All() { // TestNoAmbiguousRoutes: at most one matches
		if op.Method == method && route(op.Path, in.Path) {
			op.Path = in.Path
			return id, op, p, nil
		}
	}
	if method != http.MethodGet {
		return "", falcon.Op{}, p, fmt.Errorf("%s %s is not in the op table: a write this server cannot classify, so it refuses it", method, in.Path)
	}
	return "GET " + in.Path, falcon.Op{Method: method, Path: in.Path}, p, nil
}

// route matches a route template (/a/{id}/b) against a concrete path; {x}
// matches any one segment.
func route(template, path string) bool {
	ts, ps := strings.Split(template, "/"), strings.Split(path, "/")
	if len(ts) != len(ps) {
		return false
	}
	for i := range ts {
		if ts[i] != ps[i] && !strings.HasPrefix(ts[i], "{") {
			return false
		}
	}
	return true
}

// apiResult returns Falcon's reply with the typed tools' time conversion and
// byte cap: an envelope's resources shaped like a get, with its meta and
// errors; any other JSON capped whole; text capped as a file.
func apiResult(id string, raw json.RawMessage) (map[string]any, error) {
	var v any
	if len(raw) > 0 && json.Unmarshal(raw, &v) != nil {
		if !utf8.Valid(raw) || bytes.HasPrefix(raw, []byte("%PDF")) {
			return nil, fmt.Errorf("Falcon %s returned a binary file, which this server does not return", id)
		}
		return text(string(raw)), nil
	}
	m, _ := v.(map[string]any)
	res, ok := m["resources"]
	if !ok {
		return capObject(times(v)), nil
	}
	var out map[string]any
	if l, isList := res.([]any); isList {
		out = shape(l, nil, "", "result too large; narrow the query or lower limit", nil)
	} else {
		out = capObject(times(res))
	}
	if meta, ok := m["meta"]; ok {
		out["meta"] = meta
	}
	if errs, _ := m["errors"].([]any); len(errs) > 0 {
		out["errors"] = errs
	}
	return out, nil
}
