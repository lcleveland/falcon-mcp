// Command falcon-mcp is an MCP server for the CrowdStrike Falcon API.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	"github.com/lcleveland/falcon-mcp/internal/config"
	"github.com/lcleveland/falcon-mcp/internal/falcon"
	"github.com/lcleveland/falcon-mcp/internal/server"
	"github.com/lcleveland/falcon-mcp/internal/version"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "falcon-mcp:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cfg, warnings, err := config.Parse(args, os.Getenv)
	if errors.Is(err, flag.ErrHelp) {
		return nil
	}
	if err != nil {
		return err
	}
	if cfg.ShowVersion {
		fmt.Println(version.Version)
		return nil
	}
	// stdout belongs to the stdio transport; logs go to stderr.
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.LogLevel}))
	for _, w := range warnings {
		log.Warn(w)
	}
	log.Info("starting", "version", version.Version, "config", cfg)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	hc := &http.Client{Timeout: cfg.RequestTimeout}
	var c *falcon.Client
	if cfg.BaseURL != nil {
		c = falcon.New(cfg.Cloud, cfg.BaseURL.String(), cfg.ClientID, cfg.ClientSecret, hc, log)
	} else {
		c = falcon.New("", falcon.Clouds["us-1"], cfg.ClientID, cfg.ClientSecret, hc, log)
		cloud, err := c.Autodiscover(ctx)
		if err != nil {
			return err
		}
		log.Info("autodiscovered cloud", "cloud", cloud)
	}
	s, n := server.New(cfg, c, log)
	log.Info("registered tools", "count", n)
	return server.ServeStdio(ctx, s)
}
