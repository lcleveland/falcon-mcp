package falcon

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

const secret = "s3cr3t-client-secret"

// tenant is a fake Falcon cloud: a token endpoint plus whatever api handles.
type tenant struct {
	tokens   atomic.Int32
	revoked  atomic.Int32
	expires  int
	region   string
	tokenErr int // status to fail the token endpoint with
	api      http.HandlerFunc
}

func (f *tenant) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/oauth2/token":
		r.ParseForm()
		if f.tokenErr != 0 {
			w.WriteHeader(f.tokenErr)
			io.WriteString(w, `{"meta":{"trace_id":"tr-tok"},"errors":[{"code":403,"message":"access denied, authorization failed"}]}`)
			return
		}
		if r.PostForm.Get("client_secret") != secret || r.PostForm.Get("client_id") != "id" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		n := f.tokens.Add(1)
		exp := f.expires
		if exp == 0 {
			exp = 1799
		}
		if f.region != "" {
			w.Header().Set("X-Cs-Region", f.region)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		io.WriteString(w, `{"access_token":"tok`+strconv.Itoa(int(n))+`","expires_in":`+strconv.Itoa(exp)+`,"token_type":"bearer"}`)
	case "/oauth2/revoke":
		if id, sec, ok := r.BasicAuth(); ok && id == "id" && sec == secret {
			f.revoked.Add(1)
		}
	default:
		f.api(w, r)
	}
}

func serve(t *testing.T, f *tenant) string {
	t.Helper()
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return srv.URL
}

func newTest(t *testing.T, f *tenant) *Client {
	t.Helper()
	c := New("", serve(t, f), "id", secret, nil, nil)
	c.MaxWait, c.RetryDelay, c.SlowDown = 50*time.Millisecond, time.Millisecond, time.Millisecond
	return c
}

func status(code int, body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(code)
		io.WriteString(w, body)
	}
}

func TestTokenCreatedAndReused(t *testing.T) {
	var auth string
	f := &tenant{api: func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		io.WriteString(w, `{"resources":[]}`)
	}}
	c := newTest(t, f)
	for range 3 {
		if _, err := c.Do(context.Background(), "QueryDevicesByFilter", Params{}); err != nil {
			t.Fatal(err)
		}
	}
	if f.tokens.Load() != 1 || auth != "Bearer tok1" {
		t.Errorf("tokens = %d, auth = %q", f.tokens.Load(), auth)
	}
}

func TestEarlyRefresh(t *testing.T) {
	f := &tenant{expires: 60, api: status(200, `{}`)} // inside the 2-minute window
	c := newTest(t, f)
	c.Do(context.Background(), "QueryDevicesByFilter", Params{})
	c.Do(context.Background(), "QueryDevicesByFilter", Params{})
	if f.tokens.Load() != 2 {
		t.Errorf("tokens = %d, want a refresh per call", f.tokens.Load())
	}
}

func TestReauthOn401(t *testing.T) {
	var seen []string
	f := &tenant{}
	f.api = func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.Header.Get("Authorization"))
		if r.Header.Get("Authorization") == "Bearer tok1" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		io.WriteString(w, `{}`)
	}
	c := newTest(t, f)
	// A write too: a 401 means nothing was done, so it is safe to resend.
	if _, err := c.Do(context.Background(), "PerformActionV2", Params{}); err != nil {
		t.Fatal(err)
	}
	if strings.Join(seen, ",") != "Bearer tok1,Bearer tok2" {
		t.Errorf("seen = %v", seen)
	}

	// A second 401 is final.
	f2 := &tenant{api: status(401, `{"errors":[{"message":"access denied, invalid bearer token"}]}`)}
	_, err := newTest(t, f2).Do(context.Background(), "QueryDevicesByFilter", Params{})
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 401 || f2.tokens.Load() != 2 {
		t.Errorf("err = %v, tokens = %d", err, f2.tokens.Load())
	}
}

func TestAutodiscover(t *testing.T) {
	home := &tenant{api: status(200, `{}`)}
	homeURL := serve(t, home)

	us1 := &tenant{region: "eu-1"}
	c := newTest(t, us1)
	c.Hosts = map[string]string{"us-1": c.BaseURL(), "eu-1": homeURL}
	cloud, err := c.Autodiscover(context.Background())
	if err != nil || cloud != "eu-1" || c.Cloud() != "eu-1" || c.BaseURL() != homeURL {
		t.Fatalf("cloud = %q, base = %s, err = %v", cloud, c.BaseURL(), err)
	}
	if home.revoked.Load() != 1 {
		t.Errorf("discovery token not revoked in the home cloud")
	}
	if _, err := c.Do(context.Background(), "QueryDevicesByFilter", Params{}); err != nil || home.tokens.Load() != 1 {
		t.Errorf("home token: %v, %d", err, home.tokens.Load())
	}

	// Staying on us-1 keeps the token.
	stay := &tenant{region: "US-1"}
	c = newTest(t, stay)
	c.Hosts = map[string]string{"us-1": c.BaseURL()}
	if cloud, err := c.Autodiscover(context.Background()); err != nil || cloud != "us-1" || stay.revoked.Load() != 0 {
		t.Errorf("us-1: %q, %v, revoked %d", cloud, err, stay.revoked.Load())
	}

	// Unknown, gov and missing regions are refused; no URL comes from the header.
	for _, region := range []string{"https://evil.test", "us-gov-1", "", "eu-9"} {
		f := &tenant{region: region}
		c := newTest(t, f)
		base := c.BaseURL()
		c.Hosts = map[string]string{"us-1": base, "us-gov-1": "https://gov.test"}
		if _, err := c.Autodiscover(context.Background()); err == nil || !strings.Contains(err.Error(), "X-Cs-Region") || c.BaseURL() != base {
			t.Errorf("region %q: err = %v, base = %s", region, err, c.BaseURL())
		}
	}
}

func TestReadRetriesOn429WithEpochRetryAfter(t *testing.T) {
	for _, op := range []string{"QueryDevicesByFilter", "PostDeviceDetailsV2"} { // GET and POST reads
		var n atomic.Int32
		f := &tenant{api: func(w http.ResponseWriter, r *http.Request) {
			if n.Add(1) == 1 {
				w.Header().Set("X-RateLimit-RetryAfter", strconv.FormatInt(time.Now().Add(-time.Second).Unix(), 10))
				w.WriteHeader(http.StatusTooManyRequests)
				return
			}
			io.WriteString(w, `{}`)
		}}
		if _, err := newTest(t, f).Do(context.Background(), op, Params{}); err != nil || n.Load() != 2 {
			t.Errorf("%s: err = %v, calls = %d", op, err, n.Load())
		}
	}

	// A far-future RetryAfter is capped at MaxWait, and one retry is all.
	var n atomic.Int32
	f := &tenant{api: func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.Header().Set("X-RateLimit-RetryAfter", strconv.FormatInt(time.Now().Add(time.Hour).Unix(), 10))
		w.WriteHeader(http.StatusTooManyRequests)
	}}
	c := newTest(t, f)
	start := time.Now()
	_, err := c.Do(context.Background(), "QueryDevicesByFilter", Params{})
	if d := time.Since(start); d < c.MaxWait || d > 5*time.Second {
		t.Errorf("waited %s, want about MaxWait %s", d, c.MaxWait)
	}
	var ae *APIError
	if !errors.As(err, &ae) || ae.Status != 429 || n.Load() != 2 || !strings.Contains(ae.Hint, "retried once") {
		t.Errorf("err = %v, calls = %d", err, n.Load())
	}

	// The wait is bounded by the context.
	c.MaxWait = time.Hour
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := c.Do(ctx, "QueryDevicesByFilter", Params{}); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("ctx err = %v", err)
	}
}

func TestReadRetriesOn5xx(t *testing.T) {
	var n atomic.Int32
	f := &tenant{api: func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) == 1 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		io.WriteString(w, `{}`)
	}}
	if _, err := newTest(t, f).Do(context.Background(), "QueryDevicesByFilter", Params{}); err != nil || n.Load() != 2 {
		t.Errorf("err = %v, calls = %d", err, n.Load())
	}
}

func TestWritesNeverRetried(t *testing.T) {
	for _, op := range []string{"PerformActionV2", "UpdateDeviceTags"} { // POST and PATCH writes
		for _, code := range []int{429, 500, 503} {
			var n atomic.Int32
			f := &tenant{api: func(w http.ResponseWriter, r *http.Request) {
				n.Add(1)
				w.Header().Set("X-RateLimit-RetryAfter", "0")
				w.WriteHeader(code)
			}}
			_, err := newTest(t, f).Do(context.Background(), op, Params{})
			if err == nil || n.Load() != 1 {
				t.Errorf("%s %d: calls = %d, err = %v", op, code, n.Load(), err)
			}
			if code == 429 && !strings.Contains(err.Error(), "never retried") {
				t.Errorf("%s 429 hint: %v", op, err)
			}
		}
	}
}

func TestRequestShape(t *testing.T) {
	var got *http.Request
	var body string
	f := &tenant{api: func(w http.ResponseWriter, r *http.Request) {
		got = r
		b, _ := io.ReadAll(r.Body)
		body = string(b)
		w.WriteHeader(http.StatusNoContent)
	}}
	c := newTest(t, f)
	ctx := context.Background()

	out, err := c.Do(ctx, "indicator_get_v1", Params{Query: map[string][]string{"ids": {"a", "b c"}}})
	if err != nil || out != nil {
		t.Fatal(out, err)
	}
	if got.Method != "GET" || got.URL.Path != "/iocs/entities/indicators/v1" || got.URL.RawQuery != "ids=a&ids=b+c" {
		t.Errorf("request = %s %s", got.Method, got.URL)
	}
	if ct := got.Header.Get("Content-Type"); ct != "application/json" || body != "" {
		t.Errorf("empty body: Content-Type %q, body %q", ct, body)
	}

	if _, err := c.Do(ctx, "PostDeviceDetailsV2", Params{Body: map[string]any{"ids": []string{"x"}}}); err != nil || body != `{"ids":["x"]}` {
		t.Errorf("json body = %q, %v", body, err)
	}

	if _, err := c.Do(ctx, "StartSearchV1", Params{Path: map[string]string{"repository": "a/b"}}); err != nil || got.URL.EscapedPath() != "/humio/api/v1/repositories/a%2Fb/queryjobs" {
		t.Errorf("path param: %s, %v", got.URL.EscapedPath(), err)
	}
	for _, bad := range []map[string]string{nil, {"repository": ".."}} {
		if _, err := c.Do(ctx, "StartSearchV1", Params{Path: bad}); err == nil {
			t.Errorf("path %v accepted", bad)
		}
	}
	if _, err := c.Do(ctx, "NoSuchOp", Params{}); err == nil || !strings.Contains(err.Error(), "unknown Falcon operation") {
		t.Errorf("unknown op: %v", err)
	}

	mp := Multipart{Fields: map[string]string{"name": "f"}, FileName: "f.txt", File: []byte("data")}
	if _, err := c.Do(ctx, "PerformActionV2", Params{Body: mp}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(got.Header.Get("Content-Type"), "multipart/form-data; boundary=") || !strings.Contains(body, "data") || !strings.Contains(body, `name="file"; filename="f.txt"`) {
		t.Errorf("multipart: %s\n%s", got.Header.Get("Content-Type"), body)
	}
}

func TestPacesWhenHeadroomLow(t *testing.T) {
	f := &tenant{api: func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-RateLimit-Limit", "6000")
		w.Header().Set("X-RateLimit-Remaining", "3")
		io.WriteString(w, `{}`)
	}}
	c := newTest(t, f)
	c.SlowDown = 100 * time.Millisecond
	c.Do(context.Background(), "QueryDevicesByFilter", Params{})
	if l, r := c.RateLimit(); l != 6000 || r != 3 {
		t.Errorf("rate limit = %d/%d", r, l)
	}
	start := time.Now()
	c.Do(context.Background(), "QueryDevicesByFilter", Params{})
	if time.Since(start) < c.SlowDown {
		t.Errorf("did not slow down")
	}
}

func TestErrorHints(t *testing.T) {
	ctx := context.Background()
	body := `{"meta":{"trace_id":"tr-1"},"errors":[{"code":%d,"message":"%s"}]}`
	cases := []struct {
		op       string
		code     int
		msg      string
		wantHint string
	}{
		{"QueryDevicesByFilter", 403, "access denied, scope not permitted", "missing scope or not licensed"},
		{"QueryDevicesByFilter", 404, "route not found", "does not exist"},
		{"QueryDevicesByFilter", 400, "invalid filter", "Fix the parameters"},
		{"PerformActionV2", 500, "boom", "internal error"},
	}
	for _, tc := range cases {
		f := &tenant{api: status(tc.code, strings.NewReplacer("%d", strconv.Itoa(tc.code), "%s", tc.msg).Replace(body))}
		_, err := newTest(t, f).Do(ctx, tc.op, Params{})
		var ae *APIError
		if !errors.As(err, &ae) || ae.Status != tc.code || ae.TraceID != "tr-1" || ae.Detail != tc.msg || !strings.Contains(ae.Hint, tc.wantHint) {
			t.Errorf("%d: %#v", tc.code, ae)
		}
	}
	f := &tenant{api: status(403, `{"errors":[{"message":"access denied, scope not permitted"}]}`)}
	if _, err := newTest(t, f).Do(ctx, "QueryDevicesByFilter", Params{}); !strings.Contains(err.Error(), "needs Hosts:read") {
		t.Errorf("403 should name the scope: %v", err)
	}

	for code, want := range map[int]string{403: "IP allowlist", 401: "client ID or secret"} {
		f := &tenant{tokenErr: code}
		_, err := newTest(t, f).Do(ctx, "QueryDevicesByFilter", Params{})
		var ae *APIError
		if !errors.As(err, &ae) || ae.Status != code || !strings.Contains(ae.Hint, want) {
			t.Errorf("token %d: %v", code, err)
		}
	}
}

func TestErrorBodyCapped(t *testing.T) {
	f := &tenant{api: status(400, strings.Repeat("x", 10000))}
	_, err := newTest(t, f).Do(context.Background(), "QueryDevicesByFilter", Params{})
	var ae *APIError
	if !errors.As(err, &ae) || len(ae.Detail) > maxErrBody+len("…") {
		t.Errorf("detail is %d bytes", len(ae.Detail))
	}
}

// The secret and bearer must never reach logs or error text, even when
// Falcon echoes them back.
func TestSecretsNeverLeak(t *testing.T) {
	var logs strings.Builder
	log := slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	echo := func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		w.WriteHeader(http.StatusBadRequest)
		io.WriteString(w, `{"errors":[{"message":"bad: `+r.Header.Get("Authorization")+` `+secret+`"}]}`)
	}
	f := &tenant{api: echo}
	srv := httptest.NewServer(f)
	defer srv.Close()
	c := New("", srv.URL, "id", secret, nil, log)

	var errs []string
	if _, err := c.Do(context.Background(), "QueryDevicesByFilter", Params{}); err != nil {
		errs = append(errs, err.Error())
	}
	// A token endpoint that echoes the form back.
	tokenEcho := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		w.WriteHeader(http.StatusForbidden)
		io.WriteString(w, r.PostForm.Encode())
	}))
	defer tokenEcho.Close()
	if _, err := New("", tokenEcho.URL, "id", secret, nil, log).Authenticate(context.Background()); err != nil {
		errs = append(errs, err.Error())
	}
	// A transport error naming the URL.
	if _, err := New("", "http://127.0.0.1:1", "id", secret, nil, log).Authenticate(context.Background()); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) != 3 {
		t.Fatalf("errs = %v", errs)
	}
	all := strings.Join(errs, "\n") + logs.String()
	for _, s := range []string{secret, "tok1"} {
		if strings.Contains(all, s) {
			t.Errorf("%q leaked:\n%s", s, all)
		}
	}
	if !strings.Contains(logs.String(), "falcon request") {
		t.Errorf("no debug log line: %s", logs.String())
	}
}
