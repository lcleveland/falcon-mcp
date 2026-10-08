package tools

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
		}},
	{Name: "falcon_rtr", Group: "respond", Title: "Real Time Response",
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
