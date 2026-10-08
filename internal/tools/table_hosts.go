package tools

import (
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/lcleveland/falcon-mcp/internal/falcon"
)

var (
	hostBrief  = []string{"device_id", "hostname", "platform_name", "os_version", "local_ip", "external_ip", "last_seen", "status", "agent_version", "tags"}
	assetBrief = []string{"id", "hostname", "entity_type", "platform_name", "os_version", "current_local_ip", "last_seen_timestamp", "criticality"}
)

var hostsTools = []Tool{
	{Name: "falcon_host", Group: "hosts", Title: "Hosts",
		Description: "Hosts running the Falcon sensor: identity, OS, network, sensor version, policies and containment status.",
		Actions: []Action{
			{Name: "search", Help: "hosts matching filter; sort e.g. last_seen.desc.", Kind: Search,
				Op: "QueryDevicesByFilter", Hydrate: "PostDeviceDetailsV2", IDs: "body:ids", Brief: hostBrief,
				Guide: "falcon://hosts/search/fql-guide"},
			{Name: "get", Help: "full hosts by device id (ids).", Kind: Get, Op: "PostDeviceDetailsV2", IDs: "body:ids"},
			{Name: "add_tags", Help: "add Falcon grouping tags (tags, at most 50) to hosts by device id (ids), or by filter with confirm=<count>. Dynamic host groups can match tags, so this can change a host's policies.",
				Kind: Write, Capability: "host-tags", Op: "UpdateDeviceTags", Target: TargetIDs, Resolve: "QueryDevicesByFilter", MaxIDs: 5000,
				Inputs: []string{"tags"}, Guide: "falcon://hosts/search/fql-guide", Send: hostTags("add")},
			{Name: "remove_tags", Help: "remove Falcon grouping tags (tags) from hosts by device id (ids), or by filter with confirm=<count>.",
				Kind: Write, Capability: "host-tags", Op: "UpdateDeviceTags", Target: TargetIDs, Resolve: "QueryDevicesByFilter", MaxIDs: 5000,
				Inputs: []string{"tags"}, Guide: "falcon://hosts/search/fql-guide", Send: hostTags("remove")},
			{Name: "contain", Help: "network-contain one host by device id (id), with confirm=<its hostname>: it can then reach only the Falcon cloud. The reason is sent as the action's note.",
				Kind: Write, Capability: "containment", Op: "PerformActionV2", Target: TargetHost, Send: hostAction("contain")},
			{Name: "lift_containment", Help: "lift network containment from one host by device id (id), with confirm=<its hostname>. The reason is sent as the action's note.",
				Kind: Write, Capability: "containment", Op: "PerformActionV2", Target: TargetHost, Send: hostAction("lift_containment")},
		}},
	{Name: "falcon_host_group", Group: "hosts", Title: "Host groups",
		Description: "Host groups, which policies are assigned to, and their members.",
		Actions: []Action{
			{Name: "search", Help: "host groups matching filter.", Kind: Search, Op: "queryCombinedHostGroups",
				Brief: []string{"id", "name", "group_type", "description", "assignment_rule", "modified_timestamp"},
				Guide: "falcon://host-groups/search/fql-guide"},
			{Name: "search_members", Help: "hosts in host group id, matching filter.", Kind: Search, Op: "queryCombinedGroupMembers",
				Param: "id", Brief: hostBrief, Guide: "falcon://hosts/search/fql-guide"},
		}},
	{Name: "falcon_discover", Group: "hosts", Title: "Asset inventory",
		Description: "Falcon Discover: applications and assets found across the network, including hosts without a sensor.",
		Actions: []Action{
			{Name: "search_applications", Help: "installed applications matching filter (required), e.g. name:'Chrome'.", Kind: Search,
				Op: "combined_applications", Paging: After,
				Brief: []string{"id", "name", "vendor", "version", "software_type", "host.id"},
				Guide: "falcon://discover/applications/fql-guide"},
			{Name: "search_unmanaged_assets", Help: "assets with no Falcon sensor, matching filter.", Kind: Search,
				Op: "combined_hosts", Paging: After, Filter: "entity_type:'unmanaged'", Brief: assetBrief,
				Guide: "falcon://discover/hosts/fql-guide"},
			{Name: "search_managed_assets", Help: "sensor hosts by asset posture (encryption, Secure Boot, hardware, criticality, exposure), matching filter.", Kind: Search,
				Op: "combined_hosts", Paging: After, Filter: "entity_type:'managed'", Brief: assetBrief,
				Guide: "falcon://discover/managed-assets/fql-guide"},
		}},
	{Name: "falcon_zta", Group: "hosts", Title: "Zero Trust Assessment",
		Description: "Zero Trust Assessment scores (0-100) of hosts' sensor and OS hardening. Results name hosts by device id (aid).",
		Actions: []Action{
			{Name: "search", Help: "device ids (aid) and scores, e.g. filter score:<=50; sort score|asc for weakest first. Then get by aid for the signals.", Kind: Search,
				Op: "getAssessmentsByScoreV1", Paging: After, Filter: "score:>=0", Brief: []string{"aid", "score"}},
			{Name: "get", Help: "full assessments by device id (ids).", Kind: Get, Op: "getAssessmentV1"},
			{Name: "get_audit", Help: "the tenant-wide score summary.", Kind: Aggregate, NoFilter: true, Op: "getAuditV1"},
		}},
	{Name: "falcon_sensor_usage", Group: "hosts", Title: "Sensor usage",
		Description: "Weekly average sensor counts, as billed.",
		Actions: []Action{
			{Name: "search_weekly", Help: "weekly averages; filter e.g. event_date:'2026-09-01' or period:'28'.", Kind: Aggregate,
				Op: "GetSensorUsageWeekly", Guide: "falcon://sensor-usage/weekly/fql-guide"},
		}},
}

// maxTags is UpdateDeviceTags' limit; it fails the whole call above it.
const maxTags = 50

func hostTags(action string) func(WriteCall) (falcon.Params, error) {
	return func(w WriteCall) (falcon.Params, error) {
		tags, err := groupingTags(w.Tags)
		if err != nil {
			return falcon.Params{}, err
		}
		return falcon.Params{Body: map[string]any{"action": action, "device_ids": w.Targets, "tags": tags}}, nil
	}
}

// groupingTags puts tags in the FalconGroupingTags namespace, the one
// UpdateDeviceTags edits; Falcon compares the prefix case-sensitively.
// SensorGroupingTags are set by the sensor installer and cannot be changed.
func groupingTags(tags []string) ([]string, error) {
	const prefix = "FalconGroupingTags/"
	if len(tags) == 0 {
		return nil, errors.New("this action needs tags")
	}
	if len(tags) > maxTags {
		return nil, fmt.Errorf("at most %d tags per call", maxTags)
	}
	out := make([]string, len(tags))
	for i, t := range tags {
		t = strings.TrimSpace(t)
		if hasPrefixFold(t, "SensorGroupingTags/") {
			return nil, fmt.Errorf("tag %q is a sensor grouping tag, set by the installer; only Falcon grouping tags can change", t)
		}
		if hasPrefixFold(t, prefix) {
			t = t[len(prefix):]
		}
		if t == "" {
			return nil, errors.New("tags must not be empty")
		}
		out[i] = prefix + t
	}
	return out, nil
}

func hasPrefixFold(s, prefix string) bool {
	return len(s) >= len(prefix) && strings.EqualFold(s[:len(prefix)], prefix)
}

// hostAction is a PerformActionV2 action on one host, with the reason as
// its note.
func hostAction(name string) func(WriteCall) (falcon.Params, error) {
	return func(w WriteCall) (falcon.Params, error) {
		return falcon.Params{Query: url.Values{"action_name": {name}}, Body: map[string]any{
			"ids": w.Targets, "action_parameters": []map[string]string{{"name": "note", "value": w.Reason}}}}, nil
	}
}
