package config

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func env(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func secretFile(t *testing.T, name, v string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(v+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestSecretLookupOrder(t *testing.T) {
	flagFile := secretFile(t, "flag", "from-flag")
	envFile := secretFile(t, "env", "from-env-file")
	credDir := filepath.Dir(secretFile(t, "client-secret", "from-cred"))
	base := []string{"--cloud", "eu-1", "--client-id", "id"}

	cases := []struct {
		name string
		args []string
		env  map[string]string
		want string
		warn bool
	}{
		{"flag wins", append(base, "--client-secret-file", flagFile), map[string]string{"FALCON_CLIENT_SECRET_FILE": envFile, "FALCON_CLIENT_SECRET": "x", "CREDENTIALS_DIRECTORY": credDir}, "from-flag", false},
		{"env file", base, map[string]string{"FALCON_CLIENT_SECRET_FILE": envFile, "FALCON_CLIENT_SECRET": "x", "CREDENTIALS_DIRECTORY": credDir}, "from-env-file", false},
		{"env value warns", base, map[string]string{"FALCON_CLIENT_SECRET": " from-env ", "CREDENTIALS_DIRECTORY": credDir}, "from-env", true},
		{"systemd credential", base, map[string]string{"CREDENTIALS_DIRECTORY": credDir}, "from-cred", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c, warns, err := Parse(tc.args, env(tc.env))
			if err != nil {
				t.Fatal(err)
			}
			if c.ClientSecret != tc.want {
				t.Errorf("secret = %q, want %q", c.ClientSecret, tc.want)
			}
			if (len(warns) > 0) != tc.warn {
				t.Errorf("warnings = %v", warns)
			}
		})
	}
	if _, _, err := Parse(base, env(nil)); err == nil || !strings.Contains(err.Error(), "no client secret") {
		t.Errorf("missing secret: %v", err)
	}
}

func TestClientID(t *testing.T) {
	sec := secretFile(t, "s", "secret")
	credDir := filepath.Dir(secretFile(t, "client-id", "from-cred"))
	idFile := secretFile(t, "id", " from-file ")
	for _, tc := range []struct {
		args []string
		env  map[string]string
		want string
	}{
		{[]string{"--client-id-file", idFile, "--client-id", "flag"}, nil, "from-file"},
		{nil, map[string]string{"FALCON_CLIENT_ID": "env", "CREDENTIALS_DIRECTORY": credDir}, "env"},
		{nil, map[string]string{"CREDENTIALS_DIRECTORY": credDir}, "from-cred"},
	} {
		c, _, err := Parse(append(tc.args, "--client-secret-file", sec), env(tc.env))
		if err != nil || c.ClientID != tc.want {
			t.Errorf("%v %v: id = %v, %v; want %q", tc.args, tc.env, c, err, tc.want)
		}
	}
	if _, _, err := Parse([]string{"--client-secret-file", sec}, env(nil)); err == nil || !strings.Contains(err.Error(), "no client ID") {
		t.Errorf("missing id: %v", err)
	}
}

func TestCloudAndBaseURL(t *testing.T) {
	sec := secretFile(t, "s", "secret")
	parse := func(args ...string) (*Config, error) {
		c, _, err := Parse(append(args, "--client-id", "id", "--client-secret-file", sec), env(nil))
		return c, err
	}
	ok := map[string]string{
		"--cloud=eu-1":                     "https://api.eu-1.crowdstrike.com",
		"--cloud=us-gov-1":                 "https://api.laggar.gcw.crowdstrike.com",
		"--base-url=https://falcon.test/":  "https://falcon.test",
		"--base-url=http://127.0.0.1:8080": "http://127.0.0.1:8080",
		"--base-url=http://localhost:1":    "http://localhost:1",
		"--base-url=http://[::1]:1":        "http://[::1]:1",
	}
	for arg, want := range ok {
		c, err := parse(arg)
		if err != nil || c.BaseURL.String() != want {
			t.Errorf("%s: %v, %v; want %s", arg, c, err, want)
		}
	}
	c, err := parse()
	if err != nil || c.BaseURL != nil || c.Cloud != "" {
		t.Errorf("no cloud should autodiscover: %+v, %v", c, err)
	}
	bad := map[string][]string{
		"mutually exclusive": {"--cloud=us-1", "--base-url=https://falcon.test"},
		"unknown cloud":      {"--cloud=us-9"},
		"loopback":           {"--base-url=http://falcon.test"},
		"https URL":          {"--base-url=ftp://falcon.test"},
	}
	for want, args := range bad {
		if _, err := parse(args...); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%v: err = %v, want %q", args, err, want)
		}
	}
}

func TestLogValueRedacts(t *testing.T) {
	sec := secretFile(t, "s", "hunter2-secret")
	c, _, err := Parse([]string{"--cloud", "eu-1", "--client-id", "id", "--client-secret-file", sec}, env(nil))
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	slog.New(slog.NewTextHandler(&b, nil)).Info("x", "config", c)
	if strings.Contains(b.String(), "hunter2") || strings.Contains(fmt.Sprint(c.LogValue()), "hunter2") {
		t.Errorf("secret leaked: %s", b.String())
	}
}
