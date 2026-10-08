// Package config parses flags and environment into a Config.
//
// The client secret is only ever read from a file, a systemd credential, or,
// with a warning, the environment. There is deliberately no flag that takes a
// secret on argv, where any local user can read it from /proc/<pid>/cmdline.
package config

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/lcleveland/falcon-mcp/internal/falcon"
)

type Config struct {
	// Cloud and BaseURL are both empty when the cloud is to be autodiscovered.
	// With --base-url, Cloud stays empty.
	Cloud          string
	BaseURL        *url.URL
	ClientID       string
	ClientSecret   string
	RequestTimeout time.Duration
	LogLevel       slog.Level

	ShowVersion bool
}

// LogValue keeps secrets out of logs however the config is printed.
func (c *Config) LogValue() slog.Value {
	u := ""
	if c.BaseURL != nil {
		u = c.BaseURL.String()
	}
	return slog.GroupValue(
		slog.String("cloud", c.Cloud),
		slog.String("base_url", u),
		slog.String("client_id", c.ClientID),
		slog.Bool("client_secret_set", c.ClientSecret != ""),
		slog.Duration("request_timeout", c.RequestTimeout),
	)
}

// Parse reads args and the environment. getenv is injected for tests.
// Warnings (non-fatal) are returned for the caller to log once a logger exists.
func Parse(args []string, getenv func(string) string) (*Config, []string, error) {
	var (
		c                                     Config
		rawURL, idFile, secretFile, logLevel string
		warnings                              []string
	)
	clouds := slices.Sorted(maps.Keys(falcon.Clouds))

	fs := flag.NewFlagSet("falcon-mcp", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&c.Cloud, "cloud", getenv("FALCON_CLOUD"), "Falcon cloud: "+strings.Join(clouds, "|")+"; autodiscovered when unset, except gov clouds (env FALCON_CLOUD)")
	fs.StringVar(&rawURL, "base-url", getenv("FALCON_BASE_URL"), "Falcon API base URL, instead of --cloud (env FALCON_BASE_URL)")
	fs.StringVar(&c.ClientID, "client-id", getenv("FALCON_CLIENT_ID"), "API client ID (env FALCON_CLIENT_ID)")
	fs.StringVar(&idFile, "client-id-file", getenv("FALCON_CLIENT_ID_FILE"), "file holding the client ID, instead of --client-id (env FALCON_CLIENT_ID_FILE)")
	fs.StringVar(&secretFile, "client-secret-file", getenv("FALCON_CLIENT_SECRET_FILE"), "file holding the client secret (env FALCON_CLIENT_SECRET_FILE)")
	fs.DurationVar(&c.RequestTimeout, "request-timeout", 30*time.Second, "per-request timeout to Falcon")
	fs.StringVar(&logLevel, "log-level", or(getenv("FALCON_MCP_LOG_LEVEL"), "info"), "debug|info|warn|error (env FALCON_MCP_LOG_LEVEL)")
	fs.BoolVar(&c.ShowVersion, "version", false, "print version and exit")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fs.SetOutput(os.Stderr)
			fmt.Fprintln(os.Stderr, "Usage: falcon-mcp --client-id <id> --client-secret-file <path> [flags]")
			fs.PrintDefaults()
		}
		return nil, nil, err
	}
	if c.ShowVersion {
		return &c, nil, nil
	}
	if fs.NArg() > 0 {
		return nil, nil, fmt.Errorf("unexpected argument %q", fs.Arg(0))
	}
	if err := c.LogLevel.UnmarshalText([]byte(logLevel)); err != nil {
		return nil, nil, fmt.Errorf("--log-level: %w", err)
	}

	switch {
	case c.Cloud != "" && rawURL != "":
		return nil, nil, errors.New("--cloud and --base-url are mutually exclusive")
	case c.Cloud != "":
		host, ok := falcon.Clouds[c.Cloud]
		if !ok {
			return nil, nil, fmt.Errorf("--cloud: unknown cloud %q (want %s, or leave unset to autodiscover)", c.Cloud, strings.Join(clouds, ", "))
		}
		c.BaseURL, _ = url.Parse(host)
	case rawURL != "":
		u, err := baseURL(rawURL)
		if err != nil {
			return nil, nil, err
		}
		c.BaseURL = u
	}

	var err error
	credDir := getenv("CREDENTIALS_DIRECTORY")
	switch {
	case idFile != "":
		c.ClientID, err = readSecret(idFile)
	case c.ClientID != "":
	case credDir != "":
		c.ClientID, _ = readSecret(filepath.Join(credDir, "client-id"))
	}
	if err != nil {
		return nil, nil, err
	}
	if c.ClientID == "" {
		return nil, nil, errors.New("no client ID: set --client-id, --client-id-file, FALCON_CLIENT_ID, FALCON_CLIENT_ID_FILE or the systemd credential client-id")
	}
	// The flag defaults to FALCON_CLIENT_SECRET_FILE, so a flag beats the env.
	switch {
	case secretFile != "":
		c.ClientSecret, err = readSecret(secretFile)
	case getenv("FALCON_CLIENT_SECRET") != "":
		c.ClientSecret = strings.TrimSpace(getenv("FALCON_CLIENT_SECRET"))
		warnings = append(warnings, "client secret read from FALCON_CLIENT_SECRET; prefer --client-secret-file, the environment is readable via /proc")
	case credDir != "":
		c.ClientSecret, err = readSecret(filepath.Join(credDir, "client-secret"))
	default:
		err = errors.New("no client secret: set --client-secret-file, FALCON_CLIENT_SECRET_FILE, FALCON_CLIENT_SECRET or the systemd credential client-secret")
	}
	if err != nil {
		return nil, nil, err
	}
	return &c, warnings, nil
}

// baseURL checks --base-url. Plain http is only allowed to a loopback host
// (the VM test's stub tenant).
func baseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimRight(raw, "/"))
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("--base-url must be an https URL, got %q", raw)
	}
	if u.Scheme == "http" && !loopback(u.Host) {
		return nil, fmt.Errorf("--base-url must use https unless the host is loopback, got %q", raw)
	}
	return u, nil
}

func readSecret(path string) (string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading secret: %w", err)
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		return "", fmt.Errorf("secret file %s is empty", path)
	}
	return s, nil
}

// loopback reports whether addr ("host:port" or a bare host) is loopback.
func loopback(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = strings.Trim(addr, "[]")
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func or(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
