package tools

import (
	"errors"
	"net/url"
	"strings"

	"github.com/lcleveland/falcon-mcp/internal/falcon"
)

var (
	alertBrief      = []string{"composite_id", "product", "display_name", "status", "severity_name", "device.hostname", "host_names", "tactic", "technique", "created_timestamp"}
	caseBrief       = []string{"id", "name", "status", "severity", "assigned_to", "created_timestamp", "updated_timestamp"}
	sessionBrief    = []string{"id", "device_id", "hostname", "user_id", "origin", "created_at", "updated_at"}
	quarantineBrief = []string{"id", "sha256", "state", "hostname", "username", "paths", "date_created", "date_updated"}
)

var respondTools = []Tool{
	{Name: "falcon_alert", Group: "respond", Title: "Alerts",
		Description: "Falcon alerts (endpoint detections and other alert types), newest first by default.",
		Actions: []Action{
			{Name: "search", Help: "alerts matching filter; sort e.g. created_timestamp.desc.", Kind: Search,
				Op: "GetQueriesAlertsV2", Hydrate: "PostEntitiesAlertsV2", IDs: "body:composite_ids", Brief: alertBrief,
				Guide: "falcon://detections/search/fql-guide"},
			{Name: "get", Help: "full alerts by composite id (ids).", Kind: Get, Op: "PostEntitiesAlertsV2", IDs: "body:composite_ids"},
			{Name: "aggregate", Help: "counts and buckets; body is a list of aggregation requests [{field, type (terms|date_histogram|count|...), filter, size, name}].", Kind: Aggregate,
				Op: "PostAggregatesAlertsV2", Guide: "falcon://detections/search/fql-guide"},
			{Name: "update", Help: "update alerts by composite id (ids), or by filter with confirm=<count>. params: update_status (new|in_progress|reopened|closed), " +
				"assign_to_uuid, assign_to_user_id, assign_to_name, unassign (true), append_comment, add_tag, remove_tag (a tag or a list), remove_tags_by_prefix. " +
				"Resolve with a tag: true_positive, false_positive or ignored. The reason is added as a comment.",
				Kind: Write, Capability: "triage", Op: "PatchEntitiesAlertsV3", Target: TargetIDs, Resolve: "GetQueriesAlertsV2", MaxIDs: 1000,
				Params: alertParams, Guide: "falcon://detections/search/fql-guide", Send: alertUpdate},
		}},
	{Name: "falcon_case", Group: "respond", Title: "Cases",
		Description: "Falcon cases: the investigation records that group alerts, events and notes.",
		Actions: []Action{
			{Name: "search", Help: "cases matching filter.", Kind: Search,
				Op: "queries_cases_get_v1", Hydrate: "entities_cases_post_v2", IDs: "body:ids", Brief: caseBrief,
				Guide: "falcon://cases/search/fql-guide"},
			{Name: "get", Help: "full cases by id (ids).", Kind: Get, Op: "entities_cases_post_v2", IDs: "body:ids"},
			{Name: "list_templates", Help: "case templates matching filter.", Kind: Search,
				Op: "queries_templates_get_v1", Hydrate: "entities_templates_get_v1", Brief: []string{"id", "name", "description", "status"}},
			{Name: "aggregate_slas", Help: "SLA buckets; body is a list of aggregation requests.", Kind: Aggregate, Op: "aggregates_slas_post_v1",
				Guide: "falcon://cases/aggregates/fql-guide"},
			{Name: "aggregate_templates", Help: "template buckets; body is a list of aggregation requests.", Kind: Aggregate, Op: "aggregates_templates_post_v1",
				Guide: "falcon://cases/aggregates/fql-guide"},
			{Name: "aggregate_access_tags", Help: "access-tag buckets; body is a list of aggregation requests.", Kind: Aggregate, Op: "aggregates_access_tags_post_v1",
				Guide: "falcon://cases/aggregates/fql-guide"},
			{Name: "aggregate_notification_groups", Help: "notification-group buckets; body is a list of aggregation requests.", Kind: Aggregate, Op: "aggregates_notification_groups_post_v2",
				Guide: "falcon://cases/aggregates/fql-guide"},
			{Name: "aggregate_file_details", Help: "file buckets for case ids (ids); body is a list of aggregation requests.", Kind: Aggregate, Op: "aggregates_file_details_post_v1", TakesIDs: true,
				Guide: "falcon://cases/file-aggregates/fql-guide"},
			{Name: "create", Help: "create a case (case writes have no comment field: the reason is audit-logged only); body {name, description, severity, status, assigned_to_user_uuid, tags, template: {id}, evidence: {alerts: [{id}], events: [{id}]}}.",
				Kind: Write, Capability: "triage", Op: "entities_cases_put_v2", Inputs: []string{"body"}, Send: caseCreate},
			{Name: "update", Help: "update case id; body is the fields to set {name, description, severity, status, assigned_to_user_uuid, remove_user_assignment, custom_fields, template}.",
				Kind: Write, Capability: "triage", Op: "entities_cases_patch_v2", Inputs: []string{"id", "body"}, Send: caseUpdate},
			{Name: "add_alert_evidence", Help: "attach alerts by composite id (ids) to case id.",
				Kind: Write, Capability: "triage", Op: "entities_alert_evidence_post_v1", Target: TargetIDs, Inputs: []string{"id"}, Send: caseEvidence("alerts")},
			{Name: "add_event_evidence", Help: "attach events by id (ids) to case id.",
				Kind: Write, Capability: "triage", Op: "entities_event_evidence_post_v1", Target: TargetIDs, Inputs: []string{"id"}, Send: caseEvidence("events")},
			{Name: "add_tags", Help: "add tags to case id.",
				Kind: Write, Capability: "triage", Op: "entities_case_tags_post_v1", Inputs: []string{"id", "tags"}, Send: caseTags(true)},
			{Name: "remove_tags", Help: "remove tags from case id.",
				Kind: Write, Capability: "triage", Op: "entities_case_tags_delete_v1", Inputs: []string{"id", "tags"}, Send: caseTags(false)},
		}},
	{Name: "falcon_rtr", Group: "respond", Title: "Real Time Response", Guides: []string{"falcon://rtr/workflows/investigation-guide"},
		Description: "Real Time Response sessions and their audit trail. Opening sessions and running commands are separate, opt-in capabilities.",
		Actions: []Action{
			{Name: "search_sessions", Help: "RTR sessions matching filter.", Kind: Search,
				Op: "RTR_ListAllSessions", Hydrate: "RTR_ListSessions", IDs: "body:ids", Brief: sessionBrief,
				Guide: "falcon://rtr/sessions/search/fql-guide"},
			{Name: "search_audit_sessions", Help: "the RTR audit trail: sessions with who ran what, matching filter.", Kind: Search,
				Op: "RTRAuditSessions", Brief: sessionBrief, Guide: "falcon://rtr/audit/sessions/search/fql-guide"},
			{Name: "aggregate_sessions", Help: "session buckets; body is a list of aggregation requests.", Kind: Aggregate, Op: "RTR_AggregateSessions",
				Guide: "falcon://rtr/sessions/aggregate-guide"},
			{Name: "get_session", Help: "full sessions by id (ids).", Kind: Get, Op: "RTR_ListSessions", IDs: "body:ids"},
		}},
	{Name: "falcon_quarantine", Group: "respond", Title: "Quarantined files",
		Description: "Files the Falcon sensor quarantined on hosts.",
		Actions: []Action{
			{Name: "search", Help: "quarantined files matching filter.", Kind: Search,
				Op: "QueryQuarantineFiles", Hydrate: "GetQuarantineFiles", IDs: "body:ids", Brief: quarantineBrief,
				Guide: "falcon://quarantine/files/search/fql-guide"},
			{Name: "get", Help: "full quarantined files by id (ids).", Kind: Get, Op: "GetQuarantineFiles", IDs: "body:ids"},
			{Name: "preview_actions", Help: "how many files a release, unrelease or delete by filter would touch; filter required.", Kind: Aggregate,
				Op: "ActionUpdateCount", Guide: "falcon://quarantine/files/search/fql-guide"},
		}},
}

// alertParams are the alert action parameters triage may set, in the order
// they are sent; append_comment stays last. Suppression and show_in_ui belong to other capabilities.
var alertParams = []string{"update_status", "assign_to_uuid", "assign_to_user_id", "assign_to_name", "unassign",
	"add_tag", "remove_tag", "remove_tags_by_prefix", "append_comment"}

func alertUpdate(w WriteCall) (falcon.Params, error) {
	if len(w.Values) == 0 {
		return falcon.Params{}, errors.New("this action needs params: the updates to make")
	}
	// The caller's comments and the reason go as one comment.
	comment := append(w.Values["append_comment"], "Reason: "+w.Reason)
	if len(comment) == 1 {
		comment = []string{w.Reason}
	}
	var ap []map[string]string
	for _, name := range alertParams[:len(alertParams)-1] {
		for _, v := range w.Values[name] {
			ap = append(ap, map[string]string{"name": name, "value": v})
		}
	}
	ap = append(ap, map[string]string{"name": "append_comment", "value": strings.Join(comment, "\n\n")})
	return falcon.Params{Body: map[string]any{"composite_ids": w.Targets, "action_parameters": ap}}, nil
}

func caseCreate(w WriteCall) (falcon.Params, error) {
	b, err := object(w.Body)
	return falcon.Params{Body: b}, err
}

func caseUpdate(w WriteCall) (falcon.Params, error) {
	if w.ID == "" {
		return falcon.Params{}, errNeedsCase
	}
	b, err := object(w.Body)
	return falcon.Params{Body: map[string]any{"id": w.ID, "fields": b}}, err
}

func caseEvidence(kind string) sender {
	return func(w WriteCall) (falcon.Params, error) {
		if w.ID == "" {
			return falcon.Params{}, errNeedsCase
		}
		ev := make([]map[string]string, len(w.Targets))
		for i, id := range w.Targets {
			ev[i] = map[string]string{"id": id}
		}
		return falcon.Params{Body: map[string]any{"id": w.ID, kind: ev}}, nil
	}
}

func caseTags(add bool) sender {
	return func(w WriteCall) (falcon.Params, error) {
		switch {
		case w.ID == "":
			return falcon.Params{}, errNeedsCase
		case len(w.Tags) == 0:
			return falcon.Params{}, errNeedsTags
		case add:
			return falcon.Params{Body: map[string]any{"id": w.ID, "tags": w.Tags}}, nil
		}
		return falcon.Params{Query: url.Values{"id": {w.ID}, "tag": w.Tags}}, nil
	}
}

var errNeedsCase = errors.New("this action needs id, the case id")
