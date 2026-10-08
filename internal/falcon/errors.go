package falcon

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const maxErrBody = 2 << 10

// APIError is a non-2xx reply from Falcon. Error() is written for the model:
// what failed, Falcon's own words, and what to try next.
type APIError struct {
	Status  int
	Op      string
	Method  string
	Path    string // the op's route template, never the query string
	Scope   string // the scope the op needs, when known
	Detail  string // Falcon's errors[] messages, capped at 2 KiB
	TraceID string // CrowdStrike support asks for this
	Hint    string
}

func (e *APIError) Error() string {
	s := fmt.Sprintf("Falcon %s (%s %s): HTTP %d", e.Op, e.Method, e.Path, e.Status)
	if e.Detail != "" {
		s += ": " + e.Detail
	}
	if e.TraceID != "" {
		s += " (trace-id " + e.TraceID + ")"
	}
	if e.Hint != "" {
		s += "\nHint: " + e.Hint
	}
	return s
}

func newAPIError(id string, op Op, resp *http.Response, body []byte, scrub func(string) string) *APIError {
	e := &APIError{Status: resp.StatusCode, Op: id, Method: op.Method, Path: op.Path, Scope: op.Scope,
		TraceID: resp.Header.Get("X-Cs-Traceid")}
	var r struct {
		Errors []struct {
			Message string `json:"message"`
		} `json:"errors"`
		Meta struct {
			TraceID string `json:"trace_id"`
		} `json:"meta"`
	}
	if json.Unmarshal(body, &r) == nil {
		var msgs []string
		for _, m := range r.Errors {
			if m.Message != "" {
				msgs = append(msgs, m.Message)
			}
		}
		e.Detail = strings.Join(msgs, "; ")
		if e.TraceID == "" {
			e.TraceID = r.Meta.TraceID
		}
	}
	if e.Detail == "" {
		e.Detail = strings.TrimSpace(string(body))
	}
	e.Detail = scrub(e.Detail)
	if len(e.Detail) > maxErrBody {
		e.Detail = strings.ToValidUTF8(e.Detail[:maxErrBody], "") + "…"
	}
	e.Hint = hint(e, op.Write)
	return e
}

func hint(e *APIError, write bool) string {
	token := e.Path == tokenPath
	switch {
	case token && e.Status == http.StatusUnauthorized:
		return "the client ID or secret was rejected: check both, and that this API client exists in this cloud."
	case token && e.Status == http.StatusForbidden:
		return "the token request was refused: bad credentials, an IP allowlist on the API client that excludes this host, or a disabled client."
	case e.Status == http.StatusForbidden:
		s := "missing scope or not licensed: the API client lacks the scope for this, or the tenant is not licensed for the module (Falcon returns the same 403 for both)."
		if e.Scope != "" {
			s += " This operation needs " + e.Scope + "."
		}
		return s
	case e.Status == http.StatusUnauthorized:
		return "the access token was rejected even after re-authenticating; check the API client with falcon_status."
	case e.Status == http.StatusNotFound:
		return "no such object, or this route does not exist in this cloud. Search to find the right id."
	case e.Status == http.StatusTooManyRequests && write:
		return "Falcon is rate limiting. Writes are never retried automatically: check whether it took effect before trying again."
	case e.Status == http.StatusTooManyRequests:
		return "Falcon is rate limiting; the request was retried once and still throttled. Wait a minute and make fewer, narrower calls."
	case e.Status == http.StatusBadRequest || e.Status == http.StatusUnprocessableEntity:
		return "Falcon rejected the request; the message above names the problem. Fix the parameters or body and retry."
	case e.Status >= 500:
		return "Falcon hit an internal error; quote the trace-id if it persists."
	}
	return ""
}
