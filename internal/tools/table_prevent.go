package tools

import (
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"

	"github.com/lcleveland/falcon-mcp/internal/falcon"
)

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
		Actions: append([]Action{
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
		}, policyWrites()...)},
	{Name: "falcon_exclusion", Group: "prevent", Title: "Exclusions", TypeParam: "exclusion_type",
		Description: "Detection exclusions by exclusion_type: ioa (behavioral pattern), ml (machine learning), sensor_visibility, certificate (code-signing certificate).",
		Actions: append([]Action{
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
		}, exclusionWrites()...)},
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
			{Name: "create_rule_group", Help: "create a firewall rule group; body {name, platform, description, enabled, rules: [...]}; params clone_id (copy its rules), library (true: clone_id is from CrowdStrike's library). The reason is sent as the audit comment.",
				Kind: Write, Capability: "fleet-config", Op: "create_rule_group", Inputs: []string{"body"}, Params: []string{"clone_id", "library"}, Send: fwRuleGroup},
			{Name: "update_rule_group", Help: "change a firewall rule group: name, description, enabled, or its rules; body {id, rulegroup_version (from get_rule_groups), name, description, enabled, diff_operations, rule_ids, rule_versions, tracking}. The reason is sent as the audit comment.",
				Kind: Write, Capability: "fleet-config", Op: "update_rule_group", Inputs: []string{"body"}, Send: fwRuleGroup},
			{Name: "delete_rule_groups", Help: "delete firewall rule groups by id (ids). The reason is sent as the audit comment.",
				Kind: Write, Capability: "fleet-config", Op: "delete_rule_groups", Target: TargetIDs, MaxIDs: maxQueryIDs, Send: deleteIDs(true)},
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
			{Name: "create_rule_group", Help: "create a rule group; body {name, platform (windows|mac|linux), description}. Attach it to a prevention policy (falcon_policy perform add-rule-group) for it to apply. The reason is sent as the comment.",
				Kind: Write, Capability: "detection-add", Op: "create_rule_groupMixin0", Inputs: []string{"body"}, Send: entity("", false, true)},
			{Name: "create_rule", Help: "create a rule, disabled, in a rule group; body {rulegroup_id, name, description, ruletype_id, disposition_id, pattern_severity, field_values: [{name, label, type, values: [{label, value}]}]} (get_rule_types gives the fields). The reason is sent as the comment.",
				Kind: Write, Capability: "detection-add", Op: "create_rule", Inputs: []string{"body"}, Send: entity("", false, true)},
			{Name: "enable_rule_group", Help: "enable rule group id. The reason is sent as the comment.",
				Kind: Write, Capability: "detection-add", Op: "update_rule_groupMixin0", Inputs: []string{"id"}, Send: ioaGroupEnabled(true)},
			{Name: "enable_rules", Help: "enable rules by instance id (ids) in rule group id. The reason is sent as the comment.",
				Kind: Write, Capability: "detection-add", Op: "update_rules_v2", Target: TargetIDs, Inputs: []string{"id"}, Send: ioaRulesEnabled(true)},
			{Name: "disable_rule_group", Help: "disable rule group id. The reason is sent as the comment.",
				Kind: Write, Capability: "detection-remove", Op: "update_rule_groupMixin0", Inputs: []string{"id"}, Send: ioaGroupEnabled(false)},
			{Name: "disable_rules", Help: "disable rules by instance id (ids) in rule group id. The reason is sent as the comment.",
				Kind: Write, Capability: "detection-remove", Op: "update_rules_v2", Target: TargetIDs, Inputs: []string{"id"}, Send: ioaRulesEnabled(false)},
			{Name: "delete_rule_groups", Help: "delete rule groups, with their rules, by id (ids). The reason is sent as the comment.",
				Kind: Write, Capability: "detection-remove", Op: "delete_rule_groupsMixin0", Target: TargetIDs, MaxIDs: maxQueryIDs, Send: deleteIDs(true)},
			{Name: "delete_rules", Help: "delete rules by instance id (ids) from rule group id. The reason is sent as the comment.",
				Kind: Write, Capability: "detection-remove", Op: "delete_rules", Target: TargetIDs, MaxIDs: maxQueryIDs, Inputs: []string{"id"}, Send: ioaRulesDelete},
		}},
	{Name: "falcon_ioc", Group: "prevent", Title: "Custom IOCs",
		Description: "Custom indicators of compromise (hashes, domains, IPs) and the action Falcon takes on them.",
		Actions: []Action{
			// ponytail: offset paging stops at 10,000 IOCs (a Falcon limit); past that needs after-paging with hydration.
			{Name: "search", Help: "IOCs matching filter, e.g. type:'sha256'+expired:false; sort e.g. modified_on.desc; params from_parent (true for MSSP-parent IOCs). Pages to 10,000 results.", Kind: Search,
				Op: "indicator_search_v1", Hydrate: "indicator_get_v1", Params: []string{"from_parent"}, Brief: iocBrief, Guide: "falcon://ioc/search/fql-guide"},
			{Name: "get", Help: "full IOCs by id (ids).", Kind: Get, Op: "indicator_get_v1"},
			{Name: "create", Help: "create IOCs that detect or block; body is one indicator or a list: {type (sha256|md5|domain|ipv4|ipv6), value, action (detect|prevent|prevent_no_ui), severity, platforms, applied_globally or host_groups, expiration, description, tags}; " +
				"params retrodetects, ignore_warnings. The reason is sent as the comment.",
				Kind: Write, Capability: "detection-add", Op: "indicator_create_v1", Inputs: []string{"body"}, Params: iocParams, Send: iocCreate(iocBlock)},
			{Name: "update", Help: "set fields (body, e.g. {severity, expiration, host_groups}) on IOCs by id (ids), or by filter with confirm=<count>; action may only become detect, prevent or prevent_no_ui, and IOCs that are allow or no_action are refused (use update_allow). params retrodetects, ignore_warnings. The reason is sent as the comment.",
				Kind: Write, Capability: "detection-add", Op: "indicator_update_v1", Target: TargetIDs, Resolve: "indicator_search_v1", Inputs: []string{"body"}, Params: iocParams,
				Guide: "falcon://ioc/search/fql-guide", Send: iocUpdate(iocBlock, false)},
			{Name: "create_allow", Help: "create IOCs that Falcon allows or ignores (action allow|no_action), which lowers protection; body as for create. The reason is sent as the comment.",
				Kind: Write, Capability: "detection-remove", Op: "indicator_create_v1", Inputs: []string{"body"}, Params: iocParams, Send: iocCreate(iocAllow)},
			{Name: "update_allow", Help: "set IOCs by id (ids), or by filter with confirm=<count>, to action allow or no_action (body {action, ...other fields}), which lowers protection. The reason is sent as the comment.",
				Kind: Write, Capability: "detection-remove", Op: "indicator_update_v1", Target: TargetIDs, Resolve: "indicator_search_v1", Inputs: []string{"body"}, Params: iocParams,
				Guide: "falcon://ioc/search/fql-guide", Send: iocUpdate(iocAllow, true)},
			{Name: "delete", Help: "delete IOCs by id (ids), or by filter with confirm=<count>; at most 100 per call. The reason is sent as the comment.",
				Kind: Write, Capability: "detection-remove", Op: "indicator_delete_v1", Target: TargetIDs, Resolve: "indicator_search_v1", MaxIDs: maxQueryIDs,
				Guide: "falcon://ioc/search/fql-guide", Send: deleteIDs(true)},
		}},
}

func policyWrites() []Action {
	const (
		createHelp  = "create a policy of policy_type; body is the policy {name, platform_name, description, settings, ...} as the Falcon API takes it. New policies start disabled with no host groups."
		updateHelp  = "update policy id of policy_type; body is the fields to set, e.g. {name, description, settings}. Applies to every host in its groups at check-in. Uninstall protection can never be turned off here."
		deleteHelp  = "delete policies of policy_type by id (ids); their hosts fall back to the next policy by precedence."
		performHelp = "act on policy id of policy_type; params action_name: enable, disable, add-host-group, remove-host-group (prevention and firewall also add-rule-group, remove-rule-group; " +
			"content_update also set-pinned-content-version, remove-pinned-content-version, override-allow, override-pause, override-revert); body is the action parameters, e.g. [{name: group_id, value: <host group id>}]."
		precedenceHelp = "set the order of policies of policy_type for params platform_name: ids lists every non-default policy of that platform, highest precedence first."
	)
	var as []Action
	for _, p := range []struct{ typ, create, update, del, perform, prec, key string }{
		{"prevention", "createPreventionPolicies", "updatePreventionPolicies", "deletePreventionPolicies", "performPreventionPoliciesAction", "setPreventionPoliciesPrecedence", "resources"},
		{"sensor_update", "createSensorUpdatePoliciesV2", "updateSensorUpdatePoliciesV2", "deleteSensorUpdatePolicies", "performSensorUpdatePoliciesAction", "setSensorUpdatePoliciesPrecedence", "resources"},
		{"firewall", "createFirewallPolicies", "updateFirewallPolicies", "deleteFirewallPolicies", "performFirewallPoliciesAction", "setFirewallPoliciesPrecedence", "resources"},
		{"device_control", "postDeviceControlPoliciesV2", "patchDeviceControlPoliciesV2", "deleteDeviceControlPolicies", "performDeviceControlPoliciesAction", "setDeviceControlPoliciesPrecedence", "policies"},
		{"response", "createRTResponsePolicies", "updateRTResponsePolicies", "deleteRTResponsePolicies", "performRTResponsePoliciesAction", "setRTResponsePoliciesPrecedence", "resources"},
		{"content_update", "createContentUpdatePolicies", "updateContentUpdatePolicies", "deleteContentUpdatePolicies", "performContentUpdatePoliciesAction", "setContentUpdatePoliciesPrecedence", "resources"},
	} {
		w := Action{Type: p.typ, Kind: Write, Capability: "fleet-config"}
		as = append(as,
			with(w, Action{Name: "create", Help: createHelp, Op: p.create, Inputs: []string{"body"}, Send: policyEntity(p.key, false)}),
			with(w, Action{Name: "update", Help: updateHelp, Op: p.update, Inputs: []string{"id", "body"}, Send: policyEntity(p.key, true)}),
			with(w, Action{Name: "delete", Help: deleteHelp, Op: p.del, Target: TargetIDs, MaxIDs: maxQueryIDs, Send: deleteIDs(false)}),
			with(w, Action{Name: "perform", Help: performHelp, Op: p.perform, Inputs: []string{"id", "body"}, Params: []string{"action_name"}, Send: policyAction}),
			with(w, Action{Name: "set_precedence", Help: precedenceHelp, Op: p.prec, Target: TargetIDs, Params: []string{"platform_name"}, Send: policyPrecedence}),
		)
	}
	return as
}

func exclusionWrites() []Action {
	const (
		createHelp = "create an exclusion of exclusion_type, which lowers protection; body is one exclusion: ml {value, excluded_from (blocking|extraction), groups}, " +
			"sensor_visibility {value, groups, is_descendant_process}, ioa {name, pattern_id, pattern_name, ifn_regex, cl_regex, host_groups, ...}, " +
			"certificate {name, description, certificate: {issuer, serial, subject, thumbprint, valid_from, valid_to}, applied_globally, host_groups, status}. The reason is sent as the comment."
		updateHelp = "update exclusion id of exclusion_type; body is its fields, as for create. The reason is sent as the comment."
		deleteHelp = "delete exclusions of exclusion_type by id (ids). The reason is sent as the comment."
	)
	var as []Action
	for _, e := range []struct{ typ, create, update, del, createKey, updateKey string }{
		{"ioa", "ss_ioa_exclusions_create_v2", "ss_ioa_exclusions_update_v2", "ss_ioa_exclusions_delete_v2", "exclusions", "exclusions"},
		{"ml", "exclusions_create_v2", "exclusions_update_v2", "exclusions_delete_v2", "exclusions", ""},
		{"sensor_visibility", "createSVExclusionsV1", "updateSensorVisibilityExclusionsV1", "deleteSensorVisibilityExclusionsV1", "", ""},
		{"certificate", "cb_exclusions_create_v1", "cb_exclusions_update_v1", "cb_exclusions_delete_v1", "exclusions", "exclusions"},
	} {
		w := Action{Type: e.typ, Kind: Write, Capability: "detection-remove"}
		as = append(as,
			with(w, Action{Name: "create", Help: createHelp, Op: e.create, Inputs: []string{"body"}, Send: entity(e.createKey, false, true)}),
			with(w, Action{Name: "update", Help: updateHelp, Op: e.update, Inputs: []string{"id", "body"}, Send: entity(e.updateKey, true, true)}),
			with(w, Action{Name: "delete", Help: deleteHelp, Op: e.del, Target: TargetIDs, MaxIDs: maxQueryIDs, Send: deleteIDs(true)}),
		)
	}
	return as
}

// with fills a's type, kind and capability from w.
func with(w, a Action) Action {
	a.Type, a.Kind, a.Capability = w.Type, w.Kind, w.Capability
	return a
}

// policyEntity is entity for a policy, refusing to turn uninstall
// protection off: that is never exposed.
func policyEntity(key string, withID bool) sender {
	send := entity(key, withID, false)
	return func(w WriteCall) (falcon.Params, error) {
		if uninstallOff(w.Body) {
			return falcon.Params{}, errors.New("uninstall protection can only be ENABLED through this server; turning it off is never exposed")
		}
		return send(w)
	}
}

// uninstallOff reports whether v sets uninstall_protection anywhere to
// anything but ENABLED.
func uninstallOff(v any) bool {
	switch v := v.(type) {
	case map[string]any:
		for k, x := range v {
			if strings.EqualFold(k, "uninstall_protection") && x != "ENABLED" || uninstallOff(x) {
				return true
			}
		}
	case []any:
		return slices.ContainsFunc(v, uninstallOff)
	}
	return false
}

func policyAction(w WriteCall) (falcon.Params, error) {
	name := w.Values.Get("action_name")
	switch {
	case w.ID == "":
		return falcon.Params{}, errors.New("this action needs id, the policy id")
	case name == "":
		return falcon.Params{}, errors.New("this action needs params action_name")
	}
	b := map[string]any{"ids": []string{w.ID}}
	if w.Body != nil {
		b["action_parameters"] = w.Body
	}
	return falcon.Params{Query: url.Values{"action_name": {name}}, Body: b}, nil
}

func policyPrecedence(w WriteCall) (falcon.Params, error) {
	p := w.Values.Get("platform_name")
	if p == "" {
		return falcon.Params{}, errors.New("this action needs params platform_name")
	}
	return falcon.Params{Body: map[string]any{"ids": w.Targets, "platform_name": p}}, nil
}

// fwRuleGroup sends the body, with the reason as the audit comment.
func fwRuleGroup(w WriteCall) (falcon.Params, error) {
	b, err := object(w.Body)
	if err != nil {
		return falcon.Params{}, err
	}
	q := maps.Clone(w.Values)
	q.Set("comment", w.Reason)
	return falcon.Params{Query: q, Body: b}, nil
}

// ioaGroup reads custom IOA rule group id, whose version and fields an
// update must send back.
func ioaGroup(w WriteCall) (map[string]any, error) {
	if w.ID == "" {
		return nil, errors.New("this action needs id, the rule group id")
	}
	env, err := w.get("get_rule_groupsMixin0", falcon.Params{Query: url.Values{"ids": {w.ID}}})
	if err != nil {
		return nil, fmt.Errorf("reading rule group %s: %w", w.ID, err)
	}
	for _, x := range list(env.Resources) {
		if m, _ := x.(map[string]any); m["id"] == w.ID {
			return m, nil
		}
	}
	return nil, fmt.Errorf("no custom IOA rule group %s", w.ID)
}

func ioaGroupEnabled(on bool) sender {
	return func(w WriteCall) (falcon.Params, error) {
		g, err := ioaGroup(w)
		if err != nil {
			return falcon.Params{}, err
		}
		return falcon.Params{Body: map[string]any{"id": w.ID, "name": g["name"], "description": g["description"],
			"enabled": on, "rulegroup_version": g["version"], "comment": w.Reason}}, nil
	}
}

func ioaRulesEnabled(on bool) sender {
	return func(w WriteCall) (falcon.Params, error) {
		g, err := ioaGroup(w)
		if err != nil {
			return falcon.Params{}, err
		}
		rules := map[any]map[string]any{}
		for _, x := range list(g["rules"]) {
			if r, ok := x.(map[string]any); ok {
				rules[r["instance_id"]] = r
			}
		}
		updates := make([]map[string]any, len(w.Targets))
		for i, id := range w.Targets {
			r, ok := rules[id]
			if !ok {
				return falcon.Params{}, fmt.Errorf("rule group %s has no rule %s", w.ID, id)
			}
			u := map[string]any{"enabled": on, "rulegroup_version": g["version"]}
			for _, k := range []string{"instance_id", "name", "description", "pattern_severity", "disposition_id", "field_values"} {
				u[k] = r[k]
			}
			updates[i] = u
		}
		return falcon.Params{Body: map[string]any{"rulegroup_id": w.ID, "rulegroup_version": g["version"],
			"rule_updates": updates, "comment": w.Reason}}, nil
	}
}

func ioaRulesDelete(w WriteCall) (falcon.Params, error) {
	if w.ID == "" {
		return falcon.Params{}, errors.New("this action needs id, the rule group id")
	}
	return falcon.Params{Query: url.Values{"rule_group_id": {w.ID}, "ids": w.Targets, "comment": {w.Reason}}}, nil
}

// IOC actions: which side of protection an indicator is on.
var (
	iocBlock  = []string{"detect", "prevent", "prevent_no_ui"}
	iocAllow  = []string{"allow", "no_action"}
	iocParams = []string{"retrodetects", "ignore_warnings"}
)

// iocSide refuses an indicator whose action is not in sides, or, when
// required, has none.
func iocSide(m map[string]any, sides []string, required bool) error {
	a, set := m["action"]
	if s, _ := a.(string); (set || required) && !slices.Contains(sides, s) {
		return fmt.Errorf("indicator action must be one of %s with this action, got %v", strings.Join(sides, ", "), a)
	}
	return nil
}

func iocCreate(sides []string) sender {
	return func(w WriteCall) (falcon.Params, error) {
		items, ok := w.Body.([]any)
		if !ok {
			items = []any{w.Body}
		}
		for _, x := range items {
			m, ok := x.(map[string]any)
			if !ok || len(m) == 0 {
				return falcon.Params{}, errors.New("body must be an indicator object or a list of them")
			}
			if err := iocSide(m, sides, true); err != nil {
				return falcon.Params{}, err
			}
		}
		return falcon.Params{Query: w.Values, Body: map[string]any{"comment": w.Reason, "indicators": items}}, nil
	}
}

func iocUpdate(sides []string, required bool) sender {
	return func(w WriteCall) (falcon.Params, error) {
		b, err := object(w.Body)
		if err != nil {
			return falcon.Params{}, err
		}
		if err := iocSide(b, sides, required); err != nil {
			return falcon.Params{}, err
		}
		if !required {
			if err := noAllowIOCs(w); err != nil {
				return falcon.Params{}, err
			}
		}
		items := make([]map[string]any, len(w.Targets))
		for i, id := range w.Targets {
			items[i] = maps.Clone(b)
			items[i]["id"] = id
		}
		return falcon.Params{Query: w.Values, Body: map[string]any{"comment": w.Reason, "indicators": items}}, nil
	}
}

// noAllowIOCs refuses a block-side update that touches an allow or
// no_action IOC: widening or extending one lowers protection too.
func noAllowIOCs(w WriteCall) error {
	for ids := range slices.Chunk(w.Targets, maxQueryIDs) {
		env, err := w.get("indicator_get_v1", falcon.Params{Query: url.Values{"ids": ids}})
		if err != nil {
			return fmt.Errorf("reading IOCs to check their action: %w", err)
		}
		for _, x := range list(env.Resources) {
			if m, _ := x.(map[string]any); slices.Contains(iocAllow, fmt.Sprint(m["action"])) {
				return fmt.Errorf("IOC %v has action %v; changing it is update_allow (detection-remove)", m["id"], m["action"])
			}
		}
	}
	return nil
}
