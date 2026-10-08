package tools

import (
	"context"
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
			{Name: "search", Help: "hosts matching filter; sort e.g. last_seen.desc. Windows hostnames are cut to 15 characters, so for a longer name match its first 15 or a prefix (hostname:'PREFIX*').", Kind: Search,
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
			{Name: "suppress_detections", Help: "stop reporting detections from one host by device id (id), with confirm=<its hostname>. The reason is sent as the action's note.",
				Kind: Write, Capability: "detection-remove", Op: "PerformActionV2", Target: TargetHost, Send: hostAction("detection_suppress")},
			{Name: "unsuppress_detections", Help: "resume reporting detections from one host by device id (id), with confirm=<its hostname>.",
				Kind: Write, Capability: "detection-remove", Op: "PerformActionV2", Target: TargetHost, Send: hostAction("detection_unsuppress")},
			{Name: "hide_host", Help: "hide one host by device id (id), with confirm=<its hostname>: it leaves the console and no new detections from it are reported. unhide_host undoes it.",
				Kind: Write, Capability: "destructive", Op: "PerformActionV2", Target: TargetHost, Send: hostAction("hide_host")},
			{Name: "unhide_host", Help: "restore one hidden host by device id (id), with confirm=<its hostname>.",
				Kind: Write, Capability: "destructive", Op: "PerformActionV2", Target: TargetHost, Send: hostAction("unhide_host")},
		}},
	{Name: "falcon_host_group", Group: "hosts", Title: "Host groups",
		Description: "Host groups, which policies are assigned to, and their members.",
		Actions: []Action{
			{Name: "search", Help: "host groups matching filter.", Kind: Search, Op: "queryCombinedHostGroups",
				Brief: []string{"id", "name", "group_type", "description", "assignment_rule", "modified_timestamp"},
				Guide: "falcon://host-groups/search/fql-guide"},
			{Name: "search_members", Help: "hosts in host group id, matching filter.", Kind: Search, Op: "queryCombinedGroupMembers",
				Param: "id", Brief: hostBrief, Guide: "falcon://hosts/search/fql-guide"},
			{Name: "create", Help: "create a host group; body {name, group_type (static|dynamic|staticByID), description, assignment_rule (FQL, dynamic groups)}.",
				Kind: Write, Capability: "fleet-config", Op: "createHostGroups", Inputs: []string{"body"}, Send: entity("resources", false, false)},
			{Name: "update", Help: "update host group id; body is the fields to set {name, description, assignment_rule}. A new assignment_rule can move many hosts, and their policies, at once.",
				Kind: Write, Capability: "fleet-config", Op: "updateHostGroups", Inputs: []string{"id", "body"}, Send: entity("resources", true, false)},
			{Name: "delete", Help: "delete host groups by id (ids); their hosts lose the policies assigned through them.",
				Kind: Write, Capability: "fleet-config", Op: "deleteHostGroups", Target: TargetIDs, MaxIDs: maxQueryIDs, Send: deleteIDs(false)},
			{Name: "add_hosts", Help: "add hosts by device id (ids; find them with falcon_host search) to static host group id.",
				Kind: Write, Capability: "fleet-config", Op: "performGroupAction", Target: TargetIDs, Inputs: []string{"id"}, Send: groupMembers("add-hosts")},
			{Name: "remove_hosts", Help: "remove hosts by device id (ids; find them with falcon_host search) from static host group id.",
				Kind: Write, Capability: "fleet-config", Op: "performGroupAction", Target: TargetIDs, Inputs: []string{"id"}, Send: groupMembers("remove-hosts")},
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
			{Name: "get_audit", Help: "the tenant-wide score summary: per platform, its score, host count and gaps (signals met by fewer than all hosts, with the share that meet them); params detail (true for every signal).",
				Kind: Custom, Op: "getAuditV1", Run: ztaAudit, Params: []string{"detail"}},
		}},
	{Name: "falcon_sensor_usage", Group: "hosts", Title: "Sensor usage",
		Description: "Weekly average sensor counts, as billed.",
		Actions: []Action{
			{Name: "search_weekly", Help: "weekly averages; filter e.g. event_date:'2026-09-01' or period:'28'.", Kind: Aggregate,
				Op: "GetSensorUsageWeekly", Guide: "falcon://sensor-usage/weekly/fql-guide"},
		}},
}

// ztaAudit returns the tenant-wide ZTA summary. Each platform's audit
// holds ~70 signal ratios, mostly 1, so by default only those below 1 are
// kept, as gaps.
func ztaAudit(ctx context.Context, d Deps, in Input) (map[string]any, error) {
	detail := false
	for k, v := range in.Params {
		if k != "detail" {
			return nil, fmt.Errorf("params: %q is not a parameter of this action (takes detail)", k)
		}
		detail = v == true || v == "true"
	}
	env, err := d.call(ctx, "getAuditV1", falcon.Params{Query: url.Values{}})
	if err != nil {
		return nil, err
	}
	items := list(env.Resources)
	if !detail {
		for _, r := range items {
			r, _ := r.(map[string]any)
			for _, p := range list(r["platforms"]) {
				p, _ := p.(map[string]any)
				audit, ok := p["audit"].(map[string]any)
				if !ok {
					continue
				}
				gaps := map[string]any{}
				for k, v := range audit {
					if f, ok := v.(float64); ok && f < 1 {
						gaps[k] = f
					}
				}
				delete(p, "audit")
				p["gaps"] = gaps
			}
		}
	}
	return shape(items, in.Fields, "", noteGet, env), nil
}

// maxTags is UpdateDeviceTags' limit; it fails the whole call above it.
const maxTags = 50

func hostTags(action string) sender {
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
		return nil, errNeedsTags
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
func hostAction(name string) sender {
	return func(w WriteCall) (falcon.Params, error) {
		return falcon.Params{Query: url.Values{"action_name": {name}}, Body: map[string]any{
			"ids": w.Targets, "action_parameters": []map[string]string{{"name": "note", "value": w.Reason}}}}, nil
	}
}

// groupMembers adds or removes hosts by device id. The API takes them as a
// host filter, so ids are checked to keep them from widening it.
func groupMembers(action string) sender {
	return func(w WriteCall) (falcon.Params, error) {
		if w.ID == "" {
			return falcon.Params{}, errors.New("this action needs id, the host group id")
		}
		quoted := make([]string, len(w.Targets))
		for i, id := range w.Targets {
			if !plainID(id) {
				return falcon.Params{}, fmt.Errorf("%q is not a device id", id)
			}
			quoted[i] = "'" + id + "'"
		}
		return falcon.Params{Query: url.Values{"action_name": {action}}, Body: map[string]any{
			"ids":               []string{w.ID},
			"action_parameters": []map[string]string{{"name": "filter", "value": "device_id:[" + strings.Join(quoted, ",") + "]"}},
		}}, nil
	}
}

// plainID reports whether id has only the characters Falcon ids use.
func plainID(id string) bool {
	return id != "" && strings.IndexFunc(id, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_')
	}) < 0
}
