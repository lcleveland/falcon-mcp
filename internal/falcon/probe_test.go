package falcon

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestEveryScopeHasAProbeRoute(t *testing.T) {
	for id, op := range ops {
		if _, ok := probes[FamilyRead(op.Scope)]; !ok {
			t.Errorf("%s: no probe route for %s (family read of %s)", id, FamilyRead(op.Scope), op.Scope)
		}
	}
	for scope, pr := range probes {
		op, ok := ops[pr.op]
		if !ok || op.Method != http.MethodGet || op.Scope != scope || op.Write || strings.Contains(op.Path, "{") != (probePath[scope] != nil) {
			t.Errorf("%s: probe route %s is not a GET read under that scope, parameterless unless probePath fills it: %+v", scope, pr.op, op)
		}
	}
}

func TestFamilyRead(t *testing.T) {
	for in, want := range map[string]string{
		"Hosts:read":                        "Hosts:read",
		"Hosts:write":                       "Hosts:read",
		"NGSIEM:write":                      "NGSIEM:read",
		"Identity Protection GraphQL:write": "Identity Protection Entities:read",
	} {
		if got := FamilyRead(in); got != want {
			t.Errorf("FamilyRead(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestProbe(t *testing.T) {
	routes := map[string]http.HandlerFunc{
		"/devices/queries/devices/v1":                                      status(200, `{"resources":[]}`),
		"/alerts/queries/alerts/v2":                                        status(403, `{"errors":[{"message":"access denied, scope not permitted"}]}`),
		"/iocs/queries/indicators/v1":                                      status(429, `{}`),
		"/cases/queries/cases/v1":                                          status(503, `{}`),
		"/intel/combined/actors/v1":                                        status(404, `{}`),
		"/humio/api/v1/repositories/search-all/queryjobs/falcon-mcp-probe": status(404, `{}`),
		"/policy/queries/prevention/v1": func(w http.ResponseWriter, r *http.Request) {
			<-r.Context().Done() // hangs past the deadline
		},
	}
	var limits []string
	f := &tenant{api: func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/devices/queries/devices/v1" {
			limits = append(limits, r.URL.RawQuery)
		}
		if h, ok := routes[r.URL.Path]; ok {
			h(w, r)
			return
		}
		io.WriteString(w, `{}`)
	}}
	c := newTest(t, f)
	start := time.Now()
	p := c.Probe(context.Background(), 300*time.Millisecond)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("probe took %s, past its deadline", d)
	}
	if len(p.Results) != len(probes) {
		t.Errorf("%d results for %d probes", len(p.Results), len(probes))
	}
	want := map[string]string{
		"Hosts:read":                        ProbeOK,
		"Alerts:read":                       ProbeMissing,
		"IOC Management:read":               ProbeUnknown,
		"Cases:read":                        ProbeUnknown,
		"Actors (Falcon Intelligence):read": ProbeUnknown,
		"NGSIEM:read":                       ProbeOK,
		"Prevention Policies:read":          ProbeUnknown,
	}
	for scope, state := range want {
		if got := p.Results[scope]; got.State != state {
			t.Errorf("%s: %+v, want %s", scope, got, state)
		}
	}
	if len(limits) != 1 || limits[0] != "limit=1" {
		t.Errorf("hosts probe queries = %v", limits)
	}

	// Only a 403 hides, and a write follows its family's read.
	for scope, allowed := range map[string]bool{
		"Hosts:read": true, "Hosts:write": true, "Alerts:read": false, "Alerts:write": false,
		"IOC Management:write": true, "Cases:read": true, "Prevention Policies:read": true,
	} {
		if p.Allows(scope) != allowed {
			t.Errorf("Allows(%s) = %t", scope, !allowed)
		}
	}
	var none *Probes
	if !none.Allows("Alerts:read") || !(&Probes{}).Allows("Alerts:read") {
		t.Error("an unprobed scope must stay visible")
	}
}
