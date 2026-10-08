package tools

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

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
}

// statusOp is the cheap read whose reply carries the rate-limit headers.
const statusOp = "QueryDevicesByFilter"

func registerStatus(s *mcp.Server, d Deps) {
	mcp.AddTool(s, &mcp.Tool{
		Name:  "falcon_status",
		Title: "Falcon connectivity check",
		Description: "Check that the Falcon API client can authenticate, report the cloud and base URL, and make one " +
			"cheap authenticated read to show the rate-limit headroom. Also lists the startup scope probe: " +
			"actions whose scope reads \"missing scope or not licensed\" are hidden; restart the server after " +
			"granting a scope.\n\n" +
			"Call this first when another tool fails: it tells rejected credentials apart from a token that " +
			"works but lacks a scope.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: new(true)},
	}, func(ctx context.Context, _ *mcp.CallToolRequest, _ struct{}) (*mcp.CallToolResult, StatusOutput, error) {
		c := d.Client
		out := StatusOutput{}
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
	})
}
