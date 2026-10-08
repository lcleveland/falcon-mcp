package tools

var (
	actorBrief       = []string{"id", "name", "slug", "short_description", "known_as", "animal_classifier", "origins", "target_industries", "last_activity_date", "last_modified_date"}
	indicatorBrief   = []string{"id", "indicator", "type", "malicious_confidence", "actors", "malware_families", "threat_types", "published_date", "last_updated"}
	intelReportBrief = []string{"id", "name", "slug", "short_description", "sub_type.name", "actors", "malware", "created_date", "last_modified_date"}

	reconNotificationBrief = []string{"id", "notification.status", "notification.rule_name", "notification.rule_topic", "notification.rule_priority", "notification.item_type", "notification.item_site", "notification.created_date"}
	reconRuleBrief         = []string{"id", "name", "topic", "priority", "status", "filter", "breach_monitoring_enabled", "last_updated_timestamp"}
	reconRecordBrief       = []string{"id", "notification_id", "rule.name", "rule.topic", "source_category", "site", "user_name", "email", "exposure_date", "created_date"}
)

var intelTools = []Tool{
	{Name: "falcon_intel", Group: "intel", Title: "Threat intelligence",
		Description: "Falcon Intelligence: adversary (actor) profiles, indicators of compromise and finished intelligence reports.",
		Actions: []Action{
			{Name: "search_actors", Help: "actors matching filter, e.g. name:'FANCY BEAR' or target_industries.value:'Energy'; sort e.g. last_activity_date|desc; params q (free text).", Kind: Search,
				Op: "QueryIntelActorEntities", Query: []string{"q"}, Brief: actorBrief, Guide: "falcon://intel/actors/fql-guide"},
			{Name: "search_indicators", Help: "indicators (hashes, domains, IPs, URLs) matching filter, e.g. indicator:'evil.example.com'; sort e.g. published_date|desc; params q (free text), include_deleted, include_relations (default true, large).", Kind: Search,
				Op: "QueryIntelIndicatorEntities", Query: []string{"q", "include_deleted", "include_relations"}, Brief: indicatorBrief, Guide: "falcon://intel/indicators/fql-guide"},
			{Name: "search_reports", Help: "intelligence reports matching filter, e.g. actors.name:'FANCY BEAR'; sort e.g. created_date|desc; params q (free text).", Kind: Search,
				Op: "QueryIntelReportEntities", Query: []string{"q"}, Brief: intelReportBrief, Guide: "falcon://intel/reports/fql-guide"},
			{Name: "get_mitre_report", Help: "MITRE ATT&CK tactics and techniques of one actor; params actor_id (the numeric id from search_actors) and format (json or csv).", Kind: Aggregate,
				NoFilter: true, Op: "GetMitreReport", Query: []string{"actor_id", "format"}},
		}},
	{Name: "falcon_recon", Group: "intel", Title: "Recon (external monitoring)",
		Description: "Falcon Intelligence Recon: monitoring rules over dark-web, breach and typosquatting sources, the notifications they raise, and exposed data records.",
		Actions: []Action{
			{Name: "search_notifications", Help: "notifications matching filter, e.g. rule_topic:'SA_TYPOSQUATTING'; sort created_date.desc or updated_date.desc; params q (free text). Fields sit under notification.", Kind: Search,
				Op: "QueryNotificationsV1", Hydrate: "GetNotificationsDetailedV1", Query: []string{"q"}, Brief: reconNotificationBrief, Guide: "falcon://recon/notifications/search/fql-guide"},
			{Name: "get_notifications", Help: "full detailed notifications by id (ids).", Kind: Get, Op: "GetNotificationsDetailedV1"},
			{Name: "search_rules", Help: "monitoring rules matching filter, e.g. status:'active'+priority:'high'; sort e.g. last_updated_timestamp|desc; params q (free text).", Kind: Search,
				Op: "QueryRulesV1", Hydrate: "GetRulesV1", Query: []string{"q"}, Brief: reconRuleBrief, Guide: "falcon://recon/rules/search/fql-guide"},
			{Name: "get_rules", Help: "full monitoring rules by id (ids).", Kind: Get, Op: "GetRulesV1"},
			{Name: "search_exposed_data_records", Help: "exposed (leaked) data records matching filter, e.g. notification_id:'...' or credentials_domain:'example.com'; params q (free text).", Kind: Search,
				Op: "QueryNotificationsExposedDataRecordsV1", Hydrate: "GetNotificationsExposedDataRecordsV1", Query: []string{"q"}, Brief: reconRecordBrief, Guide: "falcon://recon/exposed-data-records/search/fql-guide"},
			{Name: "get_exposed_data_records", Help: "full exposed data records by id (ids).", Kind: Get, Op: "GetNotificationsExposedDataRecordsV1"},
			{Name: "aggregate_notifications", Help: "notification buckets; body is a list of aggregation requests [{field, type (terms|date_histogram|date_range|cardinality|...), filter, q, size, name}].", Kind: Aggregate,
				NoFilter: true, Op: "AggregateNotificationsV1", Guide: "falcon://recon/notifications/aggregate-guide"},
			{Name: "aggregate_exposed_data_records", Help: "exposed-data-record buckets; body is a list of aggregation requests.", Kind: Aggregate,
				NoFilter: true, Op: "AggregateNotificationsExposedDataRecordsV1", Guide: "falcon://recon/exposed-data-records/aggregate-guide"},
			{Name: "preview_rule", Help: "estimate a prospective rule's notifications; body is one object {topic (SA_DOMAIN|SA_EMAIL|SA_BRAND_PRODUCT|...), filter (rule FQL, e.g. (domain:'example.com')), lookback_days (7|30|180|365)}.", Kind: Aggregate,
				NoFilter: true, Op: "PreviewRuleV1", Guide: "falcon://recon/rules/preview-guide"},
		}},
}
