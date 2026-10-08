package tools

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/falcon-mcp/internal/config"
	"github.com/lcleveland/falcon-mcp/internal/falcon"
)

type RateLimit struct {
	Limit     int `json:"limit"`     // requests per minute
	Remaining int `json:"remaining"` // left in the sliding minute
}

type StatusOutput struct {
	Cloud         string     `json:"cloud,omitempty"`
	BaseURL       string     `json:"base_url"`
	Authenticated bool       `json:"authenticated"`
	TokenExpires  string     `json:"token_expires,omitempty"`
	APIReachable  bool       `json:"api_reachable"`
	RateLimit     *RateLimit `json:"rate_limit,omitempty"`
	Detail        string     `json:"detail,omitempty"`
	// The startup probe, by read scope. Only "missing scope or not
	// licensed" hides that scope's actions.
	Probe     map[string]falcon.ProbeResult `json:"probe,omitempty"`
	ProbeNote string                        `json:"probe_note,omitempty"`
	Groups    []string                      `json:"tool_groups"`
	Tools     map[string][]string           `json:"tools"`  // visible tool -> its actions
	Guides    []string                      `json:"guides"` // for action=guide
}

type statusInput struct {
	Action string `json:"action,omitempty" jsonschema:"check (the default) or guide"`
	Name   string `json:"name,omitempty" jsonschema:"for guide: the guide's name from the guides list, e.g. hosts/search/fql-guide"`
}

// statusOp is the cheap read whose reply carries the rate-limit headers.
const statusOp = "QueryDevicesByFilter"

func registerStatus(s *mcp.Server, d Deps) {
	mcp.AddTool(s, &mcp.Tool{
		Name:  "falcon_status",
		Title: "Falcon connectivity check",
		Description: "Check that the Falcon API client can authenticate, report the cloud and base URL, and make one " +
			"cheap authenticated read to show the rate-limit headroom. Lists the enabled tool groups and each visible tool's actions. Also lists the startup scope probe: " +
			"actions whose scope reads \"missing scope or not licensed\" are hidden; restart the server after " +
			"granting a scope.\n\n" +
			"Call this first when another tool fails: it tells rejected credentials apart from a token that " +
			"works but lacks a scope.\n\n" +
			"action=guide with name returns a query guide (FQL filter syntax, CQL, workflows) as markdown, the same text " +
			"as its falcon:// resource. Read an action's guide before writing its filter.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: new(true)},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, in statusInput) (*mcp.CallToolResult, any, error) {
		switch in.Action {
		case "", "check":
			return d.status(ctx)
		case "guide":
			text, err := d.guide(in.Name)
			if err != nil {
				return nil, nil, err
			}
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: text}}}, nil, nil
		}
		return nil, nil, fmt.Errorf("action %q: want check or guide", in.Action)
	})
}

func (d Deps) status(ctx context.Context) (*mcp.CallToolResult, any, error) {
	c := d.Client
	out := StatusOutput{Tools: map[string][]string{"falcon_status": {}}}
	for _, g := range config.Groups {
		if d.Config.GroupOn(g) {
			out.Groups = append(out.Groups, g)
		}
	}
	for _, t := range Tools() {
		if as := d.actions(t); len(as) > 0 {
			out.Tools[t.Name] = actionNames(as)
		}
	}
	for u := range d.guides() {
		out.Guides = append(out.Guides, strings.TrimPrefix(u, "falcon://"))
	}
	slices.Sort(out.Guides)
	if d.Probes != nil {
		out.Probe, out.ProbeNote = d.Probes.Results, d.Probes.Note
	}
	exp, err := c.Authenticate(ctx)
	out.Cloud, out.BaseURL = c.Cloud(), c.BaseURL() // after a pending autodiscovery
	if err != nil {
		out.Detail = err.Error()
		return &mcp.CallToolResult{IsError: true}, out, nil
	}
	out.Authenticated = true
	out.TokenExpires = exp.UTC().Format(time.RFC3339)

	// A 403 here only means this client lacks Hosts:read; the reply still
	// carries the rate-limit headers. Anything else is a tenant failure.
	var res *mcp.CallToolResult
	_, err = c.Do(ctx, statusOp, falcon.Params{Query: url.Values{"limit": {"1"}}})
	var ae *falcon.APIError
	switch {
	case err == nil:
		out.APIReachable = true
	case errors.As(err, &ae) && ae.Status == http.StatusForbidden:
		out.Detail = err.Error()
	default:
		out.Detail = err.Error()
		res = &mcp.CallToolResult{IsError: true}
	}
	if limit, remaining := c.RateLimit(); limit >= 0 {
		out.RateLimit = &RateLimit{Limit: limit, Remaining: remaining}
	}
	return res, out, nil
}
