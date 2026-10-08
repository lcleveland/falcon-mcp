// Package falcon is a small REST client for the CrowdStrike Falcon API:
// OAuth2 client credentials, cloud autodiscovery, operations called by
// FalconPy ID from a generated table, retries for reads only, and errors that
// tell the model what to do next.
package falcon

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Clouds maps each cloud to its API host.
var Clouds = map[string]string{
	"us-1":     "https://api.crowdstrike.com",
	"us-2":     "https://api.us-2.crowdstrike.com",
	"us-3":     "https://api.us-3.crowdstrike.com",
	"eu-1":     "https://api.eu-1.crowdstrike.com",
	"us-gov-1": "https://api.laggar.gcw.crowdstrike.com",
	"us-gov-2": "https://api.us-gov-2.crowdstrike.mil",
}

// discoverable are the clouds X-Cs-Region may send us to. Gov clouds are a
// separate identity plane and must be configured explicitly.
var discoverable = []string{"us-1", "us-2", "us-3", "eu-1"}

const (
	tokenPath    = "/oauth2/token"
	refreshEarly = 2 * time.Minute // tokens live 30 minutes
	lowHeadroom  = 10              // X-Ratelimit-Remaining at which to pace
	maxBody      = 64 << 20        // largest response read
)

type Client struct {
	clientID     string
	clientSecret string
	hc           *http.Client
	log          *slog.Logger

	mu        sync.Mutex
	cloud     string
	base      string // no trailing slash
	token     string
	expiry    time.Time
	limit     int // X-Ratelimit-Limit from the last response, -1 if unseen
	remaining int // X-Ratelimit-Remaining likewise

	// Tuning; tests shrink these.
	Hosts      map[string]string // cloud -> base URL, for autodiscovery
	MaxWait    time.Duration     // cap on an X-RateLimit-RetryAfter wait
	RetryDelay time.Duration     // wait before retrying a read after a 5xx
	SlowDown   time.Duration     // pause before each request while headroom is low
}

// New builds a client for one cloud (empty with --base-url). hc may be nil;
// its Timeout is the per-request timeout.
func New(cloud, base, clientID, clientSecret string, hc *http.Client, log *slog.Logger) *Client {
	if hc == nil {
		hc = &http.Client{Timeout: 30 * time.Second}
	}
	if log == nil {
		log = slog.New(slog.DiscardHandler)
	}
	return &Client{cloud: cloud, base: strings.TrimRight(base, "/"), clientID: clientID, clientSecret: clientSecret,
		hc: hc, log: log, limit: -1, remaining: -1,
		Hosts: Clouds, MaxWait: 60 * time.Second, RetryDelay: time.Second, SlowDown: 250 * time.Millisecond}
}

func (c *Client) BaseURL() string { c.mu.Lock(); defer c.mu.Unlock(); return c.base }
func (c *Client) Cloud() string   { c.mu.Lock(); defer c.mu.Unlock(); return c.cloud }

// RateLimit reports the rate-limit headers of the last response, -1 if unseen.
func (c *Client) RateLimit() (limit, remaining int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.limit, c.remaining
}

// Authenticate returns when the current token expires, fetching one if needed.
func (c *Client) Authenticate(ctx context.Context) (time.Time, error) {
	if _, err := c.bearer(ctx, false); err != nil {
		return time.Time{}, err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.expiry, nil
}

// Autodiscover takes a token from the configured host (us-1), reads the
// tenant's cloud from X-Cs-Region and switches to that cloud's hard-coded
// host. A URL is never built from the header. Call it before serving.
func (c *Client) Autodiscover(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	tok, expiry, h, err := c.fetchToken(ctx)
	if err != nil {
		return "", err
	}
	cloud := strings.ToLower(strings.TrimSpace(h.Get("X-Cs-Region")))
	host, ok := c.Hosts[cloud]
	if !ok || !slices.Contains(discoverable, cloud) {
		c.revoke(ctx, c.base, tok)
		return "", fmt.Errorf("cloud autodiscovery: unrecognised X-Cs-Region %.32q; set --cloud", cloud)
	}
	if host == c.base {
		c.cloud, c.token, c.expiry = cloud, tok, expiry
		return cloud, nil
	}
	// The discovery token is not used across clouds; revoke it in the
	// tenant's home cloud, as gofalcon does, and mint a fresh one there.
	c.revoke(ctx, host, tok)
	c.cloud, c.base, c.token = cloud, host, ""
	return cloud, nil
}

// bearer returns a cached token, refreshing it early or when force is set
// (after a 401). Client credentials has no refresh token, so refreshing is
// simply asking again.
func (c *Client) bearer(ctx context.Context, force bool) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if !force && c.token != "" && time.Until(c.expiry) > refreshEarly {
		return c.token, nil
	}
	tok, expiry, _, err := c.fetchToken(ctx)
	if err != nil {
		return "", err
	}
	c.token, c.expiry = tok, expiry
	return tok, nil
}

// fetchToken asks c.base for a token. The caller holds c.mu.
func (c *Client) fetchToken(ctx context.Context) (string, time.Time, http.Header, error) {
	form := url.Values{"client_id": {c.clientID}, "client_secret": {c.clientSecret}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+tokenPath, strings.NewReader(form.Encode()))
	if err != nil {
		return "", time.Time{}, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return "", time.Time{}, nil, fmt.Errorf("token request: %s", c.scrub(err.Error()))
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	resp.Body.Close()
	if resp.StatusCode/100 != 2 { // Falcon answers 201
		return "", time.Time{}, nil, newAPIError("oauth2AccessToken", Op{Method: http.MethodPost, Path: tokenPath}, resp, b, func(s string) string { return c.scrub(s) })
	}
	var t struct {
		AccessToken string  `json:"access_token"`
		ExpiresIn   float64 `json:"expires_in"`
	}
	if err := json.Unmarshal(b, &t); err != nil || t.AccessToken == "" {
		return "", time.Time{}, nil, fmt.Errorf("token request: unexpected response from %s (is the base URL a Falcon API?)", c.base)
	}
	if t.ExpiresIn <= 0 {
		t.ExpiresIn = 1800
	}
	return t.AccessToken, time.Now().Add(time.Duration(t.ExpiresIn) * time.Second), resp.Header, nil
}

// revoke is best effort: a failure only leaves a token to expire on its own.
func (c *Client) revoke(ctx context.Context, base, tok string) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, base+"/oauth2/revoke", strings.NewReader(url.Values{"token": {tok}}.Encode()))
	if err != nil {
		return
	}
	req.SetBasicAuth(c.clientID, c.clientSecret)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.hc.Do(req)
	if err != nil {
		c.log.Warn("revoking the discovery token", "error", c.scrub(err.Error(), tok))
		return
	}
	resp.Body.Close()
}

// Params are an operation's inputs. Repeated query values (ids) are sent as
// repeated parameters, which is what Falcon expects.
type Params struct {
	Path  map[string]string // fills {name} in the op's path
	Query url.Values
	Body  any // JSON-encoded, or a Multipart
}

// Multipart is a multipart/form-data body, for RTR uploads.
type Multipart struct {
	Fields   map[string]string
	FileName string // sent as the "file" part when set
	File     []byte
}

var pathParam = regexp.MustCompile(`\{\w+\}`)

// Do calls one operation and returns its raw JSON (nil for an empty body).
// Non-2xx replies return *APIError. Reads are retried once on a 429 or 5xx;
// writes never are, since Falcon takes no idempotency keys.
func (c *Client) Do(ctx context.Context, id string, p Params) (json.RawMessage, error) {
	op, ok := ops[id]
	if !ok {
		return nil, fmt.Errorf("unknown Falcon operation %q", id)
	}
	path, err := expand(op.Path, p.Path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", id, err)
	}
	if len(p.Query) > 0 {
		path += "?" + p.Query.Encode()
	}
	payload, contentType, err := encode(p.Body)
	if err != nil {
		return nil, err
	}
	reauthed := false

	for attempt := 1; ; attempt++ {
		if err := c.pace(ctx); err != nil {
			return nil, err
		}
		tok, err := c.bearer(ctx, false)
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, op.Method, c.BaseURL()+path, bytes.NewReader(payload))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Authorization", "Bearer "+tok)
		req.Header.Set("Accept", "application/json")
		// Falcon wants this even on an empty body.
		req.Header.Set("Content-Type", contentType)

		resp, err := c.hc.Do(req)
		if err != nil {
			return nil, fmt.Errorf("Falcon %s: %s", id, c.scrub(err.Error(), tok))
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("Falcon %s: reading response: %s", id, c.scrub(err.Error(), tok))
		}
		if len(b) > maxBody {
			return nil, fmt.Errorf("Falcon %s: response larger than %d MiB; narrow the request", id, maxBody>>20)
		}
		c.noteRateLimit(resp.Header)
		c.log.Debug("falcon request", "op", id, "status", resp.StatusCode, "trace_id", resp.Header.Get("X-Cs-Traceid"))

		switch {
		case resp.StatusCode/100 == 2:
			if len(bytes.TrimSpace(b)) == 0 {
				return nil, nil
			}
			return b, nil
		case resp.StatusCode == http.StatusUnauthorized && !reauthed:
			// Revoked or expired early: one fresh token, then give up.
			reauthed = true
			if _, err := c.bearer(ctx, true); err != nil {
				return nil, err
			}
			attempt--
			continue
		}
		if !op.Write && attempt == 1 {
			switch {
			case resp.StatusCode == http.StatusTooManyRequests:
				if err := sleep(ctx, c.retryAfter(resp.Header)); err != nil {
					return nil, err
				}
				continue
			case resp.StatusCode >= 500:
				if err := sleep(ctx, c.RetryDelay); err != nil {
					return nil, err
				}
				continue
			}
		}
		return nil, newAPIError(id, op, resp, b, func(s string) string { return c.scrub(s, tok) })
	}
}

// expand fills path parameters. Values are escaped, and dot segments are
// refused so a value cannot climb out of its route.
func expand(path string, params map[string]string) (string, error) {
	var err error
	out := pathParam.ReplaceAllStringFunc(path, func(m string) string {
		v := params[m[1:len(m)-1]]
		if v == "" || v == "." || v == ".." {
			err = fmt.Errorf("path parameter %s is missing or invalid", m)
			return m
		}
		return url.PathEscape(v)
	})
	return out, err
}

func encode(body any) ([]byte, string, error) {
	if mp, ok := body.(Multipart); ok {
		var b bytes.Buffer
		w := multipart.NewWriter(&b)
		for k, v := range mp.Fields {
			w.WriteField(k, v)
		}
		if mp.FileName != "" {
			fw, err := w.CreateFormFile("file", mp.FileName)
			if err != nil {
				return nil, "", err
			}
			fw.Write(mp.File)
		}
		w.Close()
		return b.Bytes(), w.FormDataContentType(), nil
	}
	if body == nil {
		return nil, "application/json", nil
	}
	j, err := json.Marshal(body)
	if err != nil {
		return nil, "", fmt.Errorf("encoding request body: %w", err)
	}
	return j, "application/json", nil
}

// noteRateLimit records an API response's headroom. The token endpoint has
// its own, separate limit, so its headers are not recorded.
func (c *Client) noteRateLimit(h http.Header) {
	limit, err1 := strconv.Atoi(h.Get("X-Ratelimit-Limit"))
	remaining, err2 := strconv.Atoi(h.Get("X-Ratelimit-Remaining"))
	if err1 != nil || err2 != nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.limit, c.remaining = limit, remaining
}

// pace slows down before the per-minute budget runs out, rather than
// running into a 429.
func (c *Client) pace(ctx context.Context) error {
	if _, remaining := c.RateLimit(); remaining >= 0 && remaining <= lowHeadroom {
		return sleep(ctx, c.SlowDown)
	}
	return nil
}

// retryAfter reads X-RateLimit-RetryAfter, a Unix epoch, capped at MaxWait.
func (c *Client) retryAfter(h http.Header) time.Duration {
	epoch, err := strconv.ParseInt(h.Get("X-Ratelimit-Retryafter"), 10, 64)
	if err != nil {
		return min(c.RetryDelay, c.MaxWait)
	}
	return max(0, min(time.Until(time.Unix(epoch, 0)), c.MaxWait))
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// scrub hides the client secret and any tokens passed in.
func (c *Client) scrub(s string, tokens ...string) string {
	for _, secret := range append(tokens, c.clientSecret) {
		if len(secret) >= 4 {
			s = strings.ReplaceAll(s, secret, "[redacted]")
		}
	}
	return s
}
