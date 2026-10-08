package tools

const (
	policySearchHelp  = "policies of policy_type matching filter; name matches use name:~'x' (name is not filterable for sensor_update and content_update); sort e.g. modified_timestamp.desc, never by platform_name."
	policyGetHelp     = "full policies of policy_type by id (ids)."
	policyMembersHelp = "hosts assigned to policy id of policy_type, matching a host filter."
	policyGuide       = "falcon://policies/search/fql-guide"
	exclSearchHelp    = "exclusions of exclusion_type matching filter; sort needs a direction, e.g. last_modified.desc (certificate: modified_on.desc). An unknown filter field returns nothing, not an error. " +
		"ioa also takes params ifn_regex, cl_regex, parent_ifn_regex, parent_cl_regex, grandparent_ifn_regex, grandparent_cl_regex."
	exclGetHelp = "full exclusions of exclusion_type by id (ids)."
	exclGuide   = "falcon://exclusions/search/fql-guide"
	fwGuide     = "falcon://firewall/rules/fql-guide"
)

var (
	policyBrief   = []string{"id", "name", "platform_name", "enabled", "description", "groups", "modified_timestamp", "modified_by"}
	ioaExclBrief  = []string{"id", "name", "pattern_id", "pattern_name", "ifn_regex", "cl_regex", "applied_globally", "host_groups", "last_modified", "modified_by"}
	mlExclBrief   = []string{"id", "value", "excluded_from", "applied_globally", "groups", "last_modified", "modified_by", "created_on"}
	svExclBrief   = []string{"id", "value", "applied_globally", "groups", "last_modified", "modified_by", "created_on"}
	certExclBrief = []string{"id", "name", "description", "status", "certificate", "applied_globally", "host_groups", "modified_on", "modified_by"}
	fwRuleBrief   = []string{"id", "name", "description", "enabled", "action", "direction", "protocol", "platform_ids", "rule_group", "modified_on"}
	fwGroupBrief  = []string{"id", "name", "description", "enabled", "platform", "rule_ids", "policy_ids", "modified_on"}
	ioaGroupBrief = []string{"id", "name", "description", "platform", "enabled", "rule_ids", "version", "modified_on", "modified_by"}
	iocBrief      = []string{"id", "type", "value", "action", "severity", "platforms", "applied_globally", "host_groups", "expiration", "source", "modified_on"}
)

var preventTools = []Tool{
	{Name: "falcon_policy", Group: "prevent", Title: "Policies", TypeParam: "policy_type",
		Description: "Falcon policies, by policy_type (the actions list the types). Each policy is assigned to host groups and has its own settings.",
		Actions: []Action{
			{Name: "search", Type: "prevention", Help: policySearchHelp, Kind: Search, Op: "queryCombinedPreventionPolicies", Brief: policyBrief, Guide: policyGuide},
			{Name: "search", Type: "sensor_update", Help: policySearchHelp, Kind: Search, Op: "queryCombinedSensorUpdatePoliciesV2", Brief: policyBrief, Guide: policyGuide},
			{Name: "search", Type: "firewall", Help: policySearchHelp, Kind: Search, Op: "queryCombinedFirewallPolicies", Brief: policyBrief, Guide: policyGuide},
			{Name: "search", Type: "device_control", Help: policySearchHelp, Kind: Search, Op: "queryDeviceControlPolicies", Hydrate: "getDeviceControlPoliciesV2", Brief: policyBrief, Guide: policyGuide},
			{Name: "search", Type: "response", Help: policySearchHelp, Kind: Search, Op: "queryCombinedRTResponsePolicies", Brief: policyBrief, Guide: policyGuide},
			{Name: "search", Type: "content_update", Help: policySearchHelp, Kind: Search, Op: "queryCombinedContentUpdatePolicies", Brief: policyBrief, Guide: policyGuide},

			{Name: "get", Type: "prevention", Help: policyGetHelp, Kind: Get, Op: "getPreventionPolicies"},
			{Name: "get", Type: "sensor_update", Help: policyGetHelp, Kind: Get, Op: "getSensorUpdatePoliciesV2"},
			{Name: "get", Type: "firewall", Help: policyGetHelp, Kind: Get, Op: "getFirewallPolicies"},
			{Name: "get", Type: "device_control", Help: policyGetHelp, Kind: Get, Op: "getDeviceControlPoliciesV2"},
			{Name: "get", Type: "response", Help: policyGetHelp, Kind: Get, Op: "getRTResponsePolicies"},
			{Name: "get", Type: "content_update", Help: policyGetHelp, Kind: Get, Op: "getContentUpdatePolicies"},

			{Name: "search_members", Type: "prevention", Help: policyMembersHelp, Kind: Search, Op: "queryCombinedPreventionPolicyMembers", Param: "id", Brief: hostBrief, Guide: "falcon://hosts/search/fql-guide"},
			{Name: "search_members", Type: "sensor_update", Help: policyMembersHelp, Kind: Search, Op: "queryCombinedSensorUpdatePolicyMembers", Param: "id", Brief: hostBrief, Guide: "falcon://hosts/search/fql-guide"},
			{Name: "search_members", Type: "firewall", Help: policyMembersHelp, Kind: Search, Op: "queryCombinedFirewallPolicyMembers", Param: "id", Brief: hostBrief, Guide: "falcon://hosts/search/fql-guide"},
			{Name: "search_members", Type: "device_control", Help: policyMembersHelp, Kind: Search, Op: "queryCombinedDeviceControlPolicyMembers", Param: "id", Brief: hostBrief, Guide: "falcon://hosts/search/fql-guide"},
			{Name: "search_members", Type: "response", Help: policyMembersHelp, Kind: Search, Op: "queryCombinedRTResponsePolicyMembers", Param: "id", Brief: hostBrief, Guide: "falcon://hosts/search/fql-guide"},
			{Name: "search_members", Type: "content_update", Help: policyMembersHelp, Kind: Search, Op: "queryCombinedContentUpdatePolicyMembers", Param: "id", Brief: hostBrief, Guide: "falcon://hosts/search/fql-guide"},
		}},
	{Name: "falcon_exclusion", Group: "prevent", Title: "Exclusions", TypeParam: "exclusion_type",
		Description: "Detection exclusions by exclusion_type: ioa (behavioral pattern), ml (machine learning), sensor_visibility, certificate (code-signing certificate).",
		Actions: []Action{
			{Name: "search", Type: "ioa", Help: exclSearchHelp, Kind: Search, Op: "ss_ioa_exclusions_search_v2", Hydrate: "ss_ioa_exclusions_get_v2", Brief: ioaExclBrief, Guide: exclGuide,
				Params: []string{"ifn_regex", "cl_regex", "parent_ifn_regex", "parent_cl_regex", "grandparent_ifn_regex", "grandparent_cl_regex"}},
			{Name: "search", Type: "ml", Help: exclSearchHelp, Kind: Search, Op: "exclusions_search_v2", Hydrate: "exclusions_get_v2", Brief: mlExclBrief, Guide: exclGuide},
			{Name: "search", Type: "sensor_visibility", Help: exclSearchHelp, Kind: Search, Op: "querySensorVisibilityExclusionsV1", Hydrate: "getSensorVisibilityExclusionsV1", Brief: svExclBrief, Guide: exclGuide},
			{Name: "search", Type: "certificate", Help: exclSearchHelp, Kind: Search, Op: "cb_exclusions_query_v1", Hydrate: "cb_exclusions_get_v1", MaxLimit: 100, Brief: certExclBrief, Guide: exclGuide},

			{Name: "get", Type: "ioa", Help: exclGetHelp, Kind: Get, Op: "ss_ioa_exclusions_get_v2"},
			{Name: "get", Type: "ml", Help: exclGetHelp, Kind: Get, Op: "exclusions_get_v2"},
			{Name: "get", Type: "sensor_visibility", Help: exclGetHelp, Kind: Get, Op: "getSensorVisibilityExclusionsV1"},
			{Name: "get", Type: "certificate", Help: exclGetHelp, Kind: Get, Op: "cb_exclusions_get_v1"},

			{Name: "get_certificate_details", Type: "certificate", Help: "code-signing certificate (issuer, subject, serial, thumbprint, validity) of a file; ids is one SHA256.", Kind: Get,
				Op: "certificates_get_v1", IDs: "one:ids"},
		}},
	{Name: "falcon_firewall", Group: "prevent", Title: "Firewall rules",
		Description: "Falcon Firewall Management rules and rule groups. Firewall policies themselves are falcon_policy with policy_type firewall.",
		Actions: []Action{
			{Name: "search_rules", Help: "firewall rules matching filter; params q (free text across string fields). platform is not a rule field.", Kind: Search,
				Op: "query_rules", Hydrate: "get_rules", Params: []string{"q"}, Brief: fwRuleBrief, Guide: fwGuide},
			{Name: "search_rule_groups", Help: "firewall rule groups matching filter; params q (free text).", Kind: Search,
				Op: "query_rule_groups", Hydrate: "get_rule_groups", Params: []string{"q"}, Brief: fwGroupBrief, Guide: fwGuide},
			{Name: "search_policy_rules", Help: "rules in firewall policy id, matching filter; params q (free text).", Kind: Search,
				Op: "query_policy_rules", Hydrate: "get_rules", Param: "id", Params: []string{"q"}, Brief: fwRuleBrief, Guide: fwGuide},
			{Name: "get_rules", Help: "full firewall rules by id (ids).", Kind: Get, Op: "get_rules"},
			{Name: "get_rule_groups", Help: "full firewall rule groups by id (ids).", Kind: Get, Op: "get_rule_groups"},
		}},
	{Name: "falcon_custom_ioa", Group: "prevent", Title: "Custom IOA rules",
		Description: "Custom Indicator of Attack rule groups and the behavioral rules inside them, plus the platforms and rule types they can use.",
		Actions: []Action{
			{Name: "search_rule_groups", Help: "rule groups with their rules, matching filter; sort e.g. modified_on.desc; params q (free text).", Kind: Search,
				Op: "query_rule_groups_full", Params: []string{"q"}, Brief: ioaGroupBrief, Guide: "falcon://custom-ioa/rule-groups/fql-guide"},
			{Name: "get_platforms", Help: "platforms a rule group can target.", Kind: Search, NoFilter: true,
				Op: "query_platformsMixin0", Hydrate: "get_platformsMixin0", Brief: []string{"id", "label"}},
			{Name: "get_rule_types", Help: "rule types with their fields and disposition ids, for building rules.", Kind: Search, NoFilter: true,
				Op: "query_rule_types", Hydrate: "get_rule_types", Brief: []string{"id", "name", "platform", "long_desc", "disposition_map", "fields"}},
			{Name: "get_rule_type", Help: "full rule types by id (ids).", Kind: Get, Op: "get_rule_types"},
		}},
	{Name: "falcon_ioc", Group: "prevent", Title: "Custom IOCs",
		Description: "Custom indicators of compromise (hashes, domains, IPs) and the action Falcon takes on them.",
		Actions: []Action{
			// ponytail: offset paging stops at 10,000 IOCs (a Falcon limit); past that needs after-paging with hydration.
			{Name: "search", Help: "IOCs matching filter, e.g. type:'sha256'+expired:false; sort e.g. modified_on.desc; params from_parent (true for MSSP-parent IOCs). Pages to 10,000 results.", Kind: Search,
				Op: "indicator_search_v1", Hydrate: "indicator_get_v1", Params: []string{"from_parent"}, Brief: iocBrief, Guide: "falcon://ioc/search/fql-guide"},
			{Name: "get", Help: "full IOCs by id (ids).", Kind: Get, Op: "indicator_get_v1"},
		}},
}
