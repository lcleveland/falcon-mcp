// Package server builds the MCP server and serves it over stdio or
// streamable HTTP.
package server

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/falcon-mcp/internal/config"
	"github.com/lcleveland/falcon-mcp/internal/falcon"
	"github.com/lcleveland/falcon-mcp/internal/tools"
	"github.com/lcleveland/falcon-mcp/internal/version"
)

// New builds the server with the enabled tools and reports how many. Call
// stop at shutdown.
func New(cfg *config.Config, c *falcon.Client, probes *falcon.Probes, log *slog.Logger) (s *mcp.Server, n int, stop func()) {
	s = mcp.NewServer(&mcp.Implementation{Name: "falcon-mcp", Title: "CrowdStrike Falcon", Version: version.Version},
		&mcp.ServerOptions{Logger: log, Instructions: instructions(c)})
	n, stop = tools.Register(s, tools.Deps{Client: c, Config: cfg, Probes: probes, Log: log})
	return s, n, stop
}

func instructions(c *falcon.Client) string {
	return "Tools for the CrowdStrike Falcon tenant at " + c.BaseURL() + ".\n\n" +
		"Call falcon_status first if anything fails: it separates rejected credentials from a missing scope.\n\n" +
		"Before writing an FQL filter or a CQL query, read the action's guide: the falcon:// resource the tool names, " +
		"or falcon_status action=guide name=<guide>. Falcon rejects or silently misreads filters on fields it does not know."
}

// tokenRetry is how long startup keeps asking for a token that failed
// without a refusal: the network (DNS, a VPN or ZTNA client) may not be up yet.
var tokenRetry = 15 * time.Second

// Probe runs the startup scope probe. Credentials the token endpoint refuses
// (or an unknown cloud) stop the server; any other token failure is retried
// for tokenRetry, then starts it with nothing probed and every action shown.
//
// shortcut: the probe never re-runs once serving; re-probing on the first
// later token would need tools re-registered under a lock, so falcon_status
// tells the operator to restart instead.
func Probe(ctx context.Context, cfg *config.Config, c *falcon.Client, log *slog.Logger) (*falcon.Probes, error) {
	if cfg.NoProbe {
		return &falcon.Probes{Note: "skipped (--no-probe)"}, nil
	}
	deadline := time.Now().Add(tokenRetry)
	for wait := time.Second; ; wait *= 2 {
		_, err := c.Authenticate(ctx)
		if err == nil {
			break
		}
		if falcon.IsFatal(err) {
			return nil, err
		}
		if time.Now().Add(wait).Before(deadline) {
			log.Warn("no token at startup; retrying", "in", wait, "error", err)
			select {
			case <-time.After(wait):
				continue
			case <-ctx.Done():
			}
		}
		why := "Falcon answered with an error"
		if ae := (*falcon.APIError)(nil); !errors.As(err, &ae) {
			why = "network error"
		}
		log.Warn("no token at startup; serving with nothing probed", "error", err)
		return &falcon.Probes{Note: "not run: no token at startup (" + why + "): " + err.Error() +
			"; every action is shown. Restart the server once Falcon is reachable to run the probe."}, nil
	}
	return c.Probe(ctx, falcon.ProbeDeadline), nil
}

// ServeStdio runs until ctx is cancelled. Nothing else may write to stdout.
func ServeStdio(ctx context.Context, s *mcp.Server) error {
	return s.Run(ctx, &mcp.StdioTransport{})
}
