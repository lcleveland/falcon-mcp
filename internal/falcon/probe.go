package falcon

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ProbeDeadline bounds the whole startup probe.
const ProbeDeadline = 10 * time.Second

// probes maps each read scope to its probe route: a cheap GET in the op
// table, with the query that keeps it to one record.
var probes = map[string]struct{ op, query string }{
	"AIDR:read":                                         {"queryAgentsV1", "limit=1"},
	"Actors (Falcon Intelligence):read":                 {"QueryIntelActorEntities", "limit=1"},
	"Alerts:read":                                       {"GetQueriesAlertsV2", "limit=1"},
	"Assets:read":                                       {"query_hosts", "limit=1"},
	"Case Templates:read":                               {"queries_templates_get_v1", "limit=1"},
	"Cases:read":                                        {"queries_cases_get_v1", "limit=1"},
	"Charlotte AI Agent Definition:read":                {"QueryAgentsV2", "limit=1"},
	"Cloud Groups V2:read":                              {"ListCloudGroupsExternal", "limit=1"},
	"Cloud Security API Assets:read":                    {"cloud_security_assets_queries", "limit=1"},
	"Cloud Security API Detections:read":                {"cspm_evaluations_iom_queries", "limit=1"},
	"Cloud Security API Risks:read":                     {"combined_cloud_risks", "limit=1"},
	"Cloud Security Policies:read":                      {"QueryRule", "limit=1"},
	"Content Update Policies:read":                      {"queryContentUpdatePolicies", "limit=1"},
	"Correlation Rules:read":                            {"combined_rules_get_v2", "limit=1"},
	"Custom IOA Rules:read":                             {"query_platformsMixin0", "limit=1"},
	"Data Protection:read":                              {"queries_classification_get_v2", "limit=1"},
	"Device Control Policies:read":                      {"queryDeviceControlPolicies", "limit=1"},
	"Falcon Container Image:read":                       {"ReadContainerCombined", "limit=1"},
	"Firewall Management:read":                          {"query_rules", "limit=1"},
	"Host Groups:read":                                  {"queryCombinedHostGroups", "limit=1"},
	"Hosts:read":                                        {"QueryDevicesByFilter", "limit=1"},
	"IOA Exclusions:read":                               {"ss_ioa_exclusions_search_v2", "limit=1"},
	"IOC Management:read":                               {"indicator_search_v1", "limit=1"},
	"Identity Protection Entities:read":                 {"QuerySensorsByFilter", "limit=1"},
	"Indicators (Falcon Intelligence):read":             {"QueryIntelIndicatorEntities", "limit=1"},
	"Machine Learning Exclusions:read":                  {"exclusions_search_v2", "limit=1"},
	"Monitoring rules (Falcon Intelligence Recon):read": {"QueryRulesV1", "limit=1"},
	"NGSIEM:read":                                       {"ListSavedQueries", "limit=1&search_domain=all"},
	"Prevention Policies:read":                          {"queryPreventionPolicies", "limit=1"},
	"Quarantined Files:read":                            {"QueryQuarantineFiles", "limit=1"},
	"Real time response:read":                           {"RTR_ListAllSessions", "limit=1"},
	"Reports (Falcon Intelligence):read":                {"QueryIntelReportEntities", "limit=1"},
	"Response Policies:read":                            {"queryRTResponsePolicies", "limit=1"},
	"SaaS Security:read":                                {"GetSupportedSaasV3", ""},
	"Scheduled Reports:read":                            {"scheduled_reports_query", "limit=1"},
	"Sensor Update Policies:read":                       {"querySensorUpdatePolicies", "limit=1"},
	"Sensor Usage:read":                                 {"GetSensorUsageWeekly", ""},
	"Sensor Visibility Exclusions:read":                 {"querySensorVisibilityExclusionsV1", "limit=1"},
	"Vulnerabilities:read":                              {"combinedQueryVulnerabilities", "limit=1&filter=status%3A%27open%27"},
	"Workflows:read":                                    {"WorkflowDefinitionsCombined", "limit=1"},
	"Zero Trust Assessment:read":                        {"getAuditV1", ""},
	"real-time-response-audit:read":                     {"RTRAuditSessions", "limit=1"},
}

// proxies name the read scope that stands in for a write scope whose family
// has no read of the same name.
var proxies = map[string]string{
	"Identity Protection GraphQL:write": "Identity Protection Entities:read",
}

// FamilyRead is the read scope whose probe decides whether an action needing
// scope is shown: scope itself for a read, its family's read for a write.
// Reads that need write scopes (NGSIEM search, Identity Protection GraphQL)
// go through this too.
func FamilyRead(scope string) string {
	if s, ok := proxies[scope]; ok {
		return s
	}
	if base, ok := strings.CutSuffix(scope, ":write"); ok {
		return base + ":read"
	}
	return scope
}

// Probe states, as falcon_status reports them.
const (
	ProbeOK      = "ok"
	ProbeMissing = "missing scope or not licensed"
	ProbeUnknown = "unknown"
)

type ProbeResult struct {
	State  string `json:"state"`
	Status int    `json:"status,omitempty"` // HTTP status, 0 if none came back
	Detail string `json:"detail,omitempty"`
}

// Probes is the outcome of the startup probe. The zero value (nothing
// probed) shows everything.
type Probes struct {
	Results map[string]ProbeResult // by read scope
	Note    string                 // why the probe did not run, if it did not
}

// Allows reports whether actions needing scope stay visible: everything but
// a scope whose family read was refused with a 403.
func (p *Probes) Allows(scope string) bool {
	if p == nil {
		return true
	}
	return p.Results[FamilyRead(scope)].State != ProbeMissing
}

// Probe runs every probe route concurrently under deadline. Only a 403 hides
// a scope; anything uncertain fails open.
func (c *Client) Probe(ctx context.Context, deadline time.Duration) *Probes {
	ctx, cancel := context.WithTimeout(ctx, deadline)
	defer cancel()
	p := &Probes{Results: map[string]ProbeResult{}}
	var mu sync.Mutex
	var wg sync.WaitGroup
	for scope, pr := range probes {
		wg.Go(func() {
			q, _ := url.ParseQuery(pr.query)
			_, err := c.Do(ctx, pr.op, Params{Query: q})
			r := classify(err)
			switch {
			case r.State == ProbeMissing:
				c.log.Info("probe: scope missing or not licensed; hiding its actions", "scope", scope, "detail", r.Detail)
			case r.Status == http.StatusNotFound:
				c.log.Error("probe route not found; this is a bug in the probe table", "scope", scope, "op", pr.op)
			case r.State == ProbeUnknown:
				c.log.Warn("probe inconclusive; showing the scope's actions", "scope", scope, "detail", r.Detail)
			}
			mu.Lock()
			p.Results[scope] = r
			mu.Unlock()
		})
	}
	wg.Wait()
	return p
}

func classify(err error) ProbeResult {
	if err == nil {
		return ProbeResult{State: ProbeOK}
	}
	var ae *APIError
	if errors.As(err, &ae) {
		r := ProbeResult{State: ProbeUnknown, Status: ae.Status, Detail: ae.Detail}
		if ae.Status == http.StatusForbidden && tokenError(err) == nil {
			r.State = ProbeMissing
		}
		return r
	}
	return ProbeResult{State: ProbeUnknown, Detail: err.Error()}
}
