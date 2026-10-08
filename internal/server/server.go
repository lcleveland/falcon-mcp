// Package server builds the MCP server and serves it over stdio.
package server

import (
	"context"
	"log/slog"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/lcleveland/falcon-mcp/internal/config"
	"github.com/lcleveland/falcon-mcp/internal/falcon"
	"github.com/lcleveland/falcon-mcp/internal/tools"
	"github.com/lcleveland/falcon-mcp/internal/version"
)

// New builds the server with the enabled tools and reports how many.
func New(cfg *config.Config, c *falcon.Client, log *slog.Logger) (*mcp.Server, int) {
	s := mcp.NewServer(&mcp.Implementation{Name: "falcon-mcp", Title: "CrowdStrike Falcon", Version: version.Version},
		&mcp.ServerOptions{Logger: log, Instructions: instructions(c)})
	return s, tools.Register(s, tools.Deps{Client: c, Config: cfg, Log: log})
}

func instructions(c *falcon.Client) string {
	return "Tools for the CrowdStrike Falcon tenant at " + c.BaseURL() + ".\n\n" +
		"Call falcon_status first if anything fails: it separates rejected credentials from a missing scope."
}

// ServeStdio runs until ctx is cancelled. Nothing else may write to stdout.
func ServeStdio(ctx context.Context, s *mcp.Server) error {
	return s.Run(ctx, &mcp.StdioTransport{})
}
