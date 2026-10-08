package tools

var (
	hostBrief  = []string{"device_id", "hostname", "platform_name", "os_version", "local_ip", "external_ip", "last_seen", "status", "agent_version", "tags"}
	assetBrief = []string{"id", "hostname", "entity_type", "platform_name", "os_version", "current_local_ip", "last_seen_timestamp", "criticality"}
)

var hostsTools = []Tool{
	{Name: "falcon_host", Group: "hosts", Title: "Hosts",
		Description: "Hosts running the Falcon sensor: identity, OS, network, sensor version, policies and containment status.",
		Actions: []Action{
			{Name: "search", Help: "hosts matching filter; sort e.g. last_seen.desc.", Kind: Search,
				Op: "QueryDevicesByFilter", Get: "PostDeviceDetailsV2", IDs: "body:ids", Brief: hostBrief,
				Guide: "falcon://hosts/search/fql-guide"},
			{Name: "get", Help: "full hosts by device id (ids).", Kind: Get, Op: "PostDeviceDetailsV2", IDs: "body:ids"},
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
				Op: "combined_applications", Paging: After, MaxLimit: 1000,
				Brief: []string{"id", "name", "vendor", "version", "software_type", "host.id"},
				Guide: "falcon://discover/applications/fql-guide"},
			{Name: "search_unmanaged_assets", Help: "assets with no Falcon sensor, matching filter.", Kind: Search,
				Op: "combined_hosts", Paging: After, MaxLimit: 1000, Filter: "entity_type:'unmanaged'", Brief: assetBrief,
				Guide: "falcon://discover/hosts/fql-guide"},
			{Name: "search_managed_assets", Help: "sensor hosts by asset posture (encryption, Secure Boot, hardware, criticality, exposure), matching filter.", Kind: Search,
				Op: "combined_hosts", Paging: After, MaxLimit: 1000, Filter: "entity_type:'managed'", Brief: assetBrief,
				Guide: "falcon://discover/managed-assets/fql-guide"},
		}},
	{Name: "falcon_zta", Group: "hosts", Title: "Zero Trust Assessment",
		Description: "Zero Trust Assessment scores (0-100) of hosts' sensor and OS hardening. Results name hosts by device id (aid).",
		Actions: []Action{
			{Name: "search", Help: "device ids (aid) and scores, e.g. filter score:<=50; sort score|asc for weakest first. Then get by aid for the signals.", Kind: Search,
				Op: "getAssessmentsByScoreV1", Paging: After, MaxLimit: 1000, Filter: "score:>=0", Brief: []string{"aid", "score"}},
			{Name: "get", Help: "full assessments by device id (ids).", Kind: Get, Op: "getAssessmentV1"},
			{Name: "get_audit", Help: "the tenant-wide score summary.", Kind: Aggregate, Op: "getAuditV1"},
		}},
	{Name: "falcon_sensor_usage", Group: "hosts", Title: "Sensor usage",
		Description: "Weekly average sensor counts, as billed.",
		Actions: []Action{
			{Name: "search_weekly", Help: "weekly averages; filter e.g. event_date:'2026-09-01' or period:'28'.", Kind: Aggregate,
				Op: "GetSensorUsageWeekly", Guide: "falcon://sensor-usage/weekly/fql-guide"},
		}},
}
